#include "ast/passes/pre_type_check.h"

#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <variant>

#include "arch/arch.h"
#include "ast/ast.h"
#include "ast/helpers.h"
#include "ast/passes/map_sugar.h"
#include "ast/visitor.h"
#include "bpfmap.h"
#include "bpftrace.h"
#include "format_string.h"
#include "log.h"
#include "output/output.h"
#include "probe_types.h"

namespace bpftrace::ast {

namespace {

using VarOrigin = std::
    variant<VarDeclStatement *, AssignVarStatement *, SubprogArg *, Variable *>;

struct VarInfo {
  VarOrigin origin;
  bool was_assigned;
};

using Scope = Node *;

void add_origin_context(Diagnostic &d, const VarOrigin &origin)
{
  std::visit(
      [&d](auto &&arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, VarDeclStatement *>) {
          d.addContext(arg->loc) << "This is the initial declaration.";
        } else if constexpr (std::is_same_v<T, AssignVarStatement *>) {
          d.addContext(arg->loc) << "This is the initial assignment.";
        } else if constexpr (std::is_same_v<T, SubprogArg *>) {
          d.addContext(arg->loc) << "This is the function parameter.";
        } else if constexpr (std::is_same_v<T, Variable *>) {
          d.addContext(arg->loc) << "This is the loop variable.";
        }
      },
      origin);
}

class VariablePreCheck : public Visitor<VariablePreCheck> {
public:
  using Visitor<VariablePreCheck>::visit;

  void visit(AssignVarStatement &assignment);
  void visit(BlockExpr &block);
  void visit(For &f);
  void visit(Offsetof &offof);
  void visit(Probe &probe);
  void visit(Sizeof &szof);
  void visit(Subprog &subprog);
  void visit(SubprogArg &arg);
  void visit(Typeof &typeof_);
  void visit(Typeinfo &typeinfo);
  void visit(VarDeclStatement &decl);
  void visit(Variable &var);
  void visit(VariableAddr &var_addr);

private:
  VarInfo *find_variable(const std::string &name);
  void check_variable_decls();
  std::vector<Scope> scope_stack_;
  std::map<Scope, std::map<std::string, VarInfo>> variables_;
  uint32_t meta_depth_ = 0; // sizeof, offsetof, typeof, typeinfo
};

VarInfo *VariablePreCheck::find_variable(const std::string &name)
{
  for (auto *scope : scope_stack_) {
    if (auto scope_it = variables_.find(scope); scope_it != variables_.end()) {
      if (auto var_it = scope_it->second.find(name);
          var_it != scope_it->second.end()) {
        return &var_it->second;
      }
    }
  }
  return nullptr;
}

void VariablePreCheck::check_variable_decls()
{
  for (const auto &[scope, var_map] : variables_) {
    for (const auto &[ident, info] : var_map) {
      if (info.was_assigned) {
        continue;
      }
      if (const auto *decl = std::get_if<VarDeclStatement *>(&info.origin)) {
        (*decl)->addWarning()
            << "Variable " << ident << " was never assigned to.";
      }
    }
  }
}

void VariablePreCheck::visit(AssignVarStatement &assignment)
{
  visit(assignment.expr);

  if (std::holds_alternative<VarDeclStatement *>(assignment.var_decl)) {
    visit(assignment.var_decl);
  }

  const std::string &var_ident = assignment.var()->ident;
  if (auto *info = find_variable(var_ident)) {
    info->was_assigned = true;
  } else if (!scope_stack_.empty()) {
    variables_[scope_stack_.back()][var_ident] = VarInfo{
      .origin = &assignment, .was_assigned = true
    };
  }
}

void VariablePreCheck::visit(BlockExpr &block)
{
  scope_stack_.push_back(&block);
  Visitor<VariablePreCheck>::visit(block);
  scope_stack_.pop_back();
}

void VariablePreCheck::visit(For &f)
{
  const auto &decl_name = f.decl->ident;
  if (const auto *info = find_variable(decl_name)) {
    auto &err = f.decl->addError();
    err << "Loop declaration shadows existing variable: " + decl_name;
    add_origin_context(err, info->origin);
  }

  visit(f.iterable);

  scope_stack_.push_back(&f);
  // Loop variable is always assigned
  variables_[&f][decl_name] = VarInfo{ .origin = f.decl, .was_assigned = true };

  visit(f.block);

  scope_stack_.pop_back();
}

void VariablePreCheck::visit(Offsetof &offof)
{
  meta_depth_++;
  Visitor<VariablePreCheck>::visit(offof);
  meta_depth_--;
}

void VariablePreCheck::visit(Probe &probe)
{
  scope_stack_.push_back(&probe);
  Visitor<VariablePreCheck>::visit(probe);
  check_variable_decls();
  scope_stack_.pop_back();
}

void VariablePreCheck::visit(Sizeof &szof)
{
  meta_depth_++;
  Visitor<VariablePreCheck>::visit(szof);
  meta_depth_--;
}

void VariablePreCheck::visit(Subprog &subprog)
{
  scope_stack_.push_back(&subprog);

  // Function parameters are always assigned
  for (auto *arg : subprog.args) {
    variables_[&subprog][arg->var->ident] = VarInfo{ .origin = arg,
                                                     .was_assigned = true };
  }
  visit(subprog.args);
  visit(subprog.block);
  visit(subprog.return_type);

  check_variable_decls();
  scope_stack_.pop_back();
}

void VariablePreCheck::visit(SubprogArg &arg)
{
  // Only visit typeof, not the variable being defined as a parameter
  visit(arg.typeof);
}

void VariablePreCheck::visit(Typeof &typeof_)
{
  meta_depth_++;
  Visitor<VariablePreCheck>::visit(typeof_);
  meta_depth_--;
}

void VariablePreCheck::visit(Typeinfo &typeinfo)
{
  meta_depth_++;
  Visitor<VariablePreCheck>::visit(typeinfo);
  meta_depth_--;
}

void VariablePreCheck::visit(VarDeclStatement &decl)
{
  // Only visit typeof, not the variable being declared
  visit(decl.typeof);

  const std::string &var_ident = decl.var->ident;

  if (const auto *info = find_variable(var_ident)) {
    auto &err = decl.addError();
    err << "Variable " << var_ident
        << " was already declared. Variable shadowing is not "
           "allowed.";
    add_origin_context(err, info->origin);
    return;
  }

  // Declaration without assignment - was_assigned = false
  if (!scope_stack_.empty()) {
    variables_[scope_stack_.back()][var_ident] = VarInfo{
      .origin = &decl, .was_assigned = false
    };
  }
}

void VariablePreCheck::visit(Variable &var)
{
  if (auto *info = find_variable(var.ident)) {
    if (!info->was_assigned && meta_depth_ == 0) {
      var.addWarning() << "Variable used before it was assigned: " << var.ident;
    }
  } else {
    var.addError() << "Undefined or undeclared variable: " << var.ident;
  }
}

void VariablePreCheck::visit(VariableAddr &var_addr)
{
  if (auto *found = find_variable(var_addr.var->ident)) {
    // We can't know if the pointer to a scratch variable was passed
    // to an external function for assignment so just mark it as assigned.
    found->was_assigned = true;
  } else {
    var_addr.var->addError()
        << "Undefined or undeclared variable: " << var_addr.var->ident;
  }
}

bool check_symbol(const Call &call)
{
  auto *arg = call.vargs.at(0).as<String>();
  if (!arg) {
    call.addError() << call.func
                    << "() expects a string literal as the first argument";
    return false;
  }

  std::string re = "^[a-zA-Z0-9./_-]+$";
  bool is_valid = std::regex_match(arg->value, std::regex(re));
  if (!is_valid) {
    call.addError() << call.func
                    << "() expects a string that is a valid symbol (" << re
                    << ") as input (\"" << arg << "\" provided)";
    return false;
  }

  return true;
}

struct nargs_spec {
  size_t min_args = 0;
  size_t max_args = 0;
};

// clang-format off
const std::map<std::string, nargs_spec> CALL_NARGS = {
  { "__builtin_uaddr", { .min_args=1, .max_args=1 } },
  { "avg",            { .min_args=3, .max_args=3 } },
  { "bswap",          { .min_args=1, .max_args=1 } },
  { "buf",            { .min_args=1, .max_args=2 } },
  { "cat",            { .min_args=1, .max_args=128 } },
  { "cgroup_path",    { .min_args=1, .max_args=2 } },
  { "cgroupid",       { .min_args=1, .max_args=1 } },
  { "clear",          { .min_args=1, .max_args=1 } },
  { "count",          { .min_args=2, .max_args=2 } },
  { "debugf",         { .min_args=1, .max_args=128 } },
  { "errorf",         { .min_args=1, .max_args=128 } },
  { "exit",           { .min_args=0, .max_args=1 } },
  { "fail",           { .min_args=1, .max_args=128 } },
  { "hist",           { .min_args=3, .max_args=4 } },
  { "join",           { .min_args=1, .max_args=2 } },
  { "kaddr",          { .min_args=1, .max_args=1 } },
  { "kptr",           { .min_args=1, .max_args=1 } },
  { "kstack",         { .min_args=0, .max_args=2 } },
  { "ksym",           { .min_args=1, .max_args=1 } },
  { "lhist",          { .min_args=6, .max_args=6 } },
  { "macaddr",        { .min_args=1, .max_args=1 } },
  { "max",            { .min_args=3, .max_args=3 } },
  { "min",            { .min_args=3, .max_args=3 } },
  { "nsecs",          { .min_args=0, .max_args=1 } },
  { "ntop",           { .min_args=1, .max_args=2 } },
  { "offsetof",       { .min_args=2, .max_args=2 } },
  { "path",           { .min_args=1, .max_args=2 } },
  { "percpu_kaddr",   { .min_args=1, .max_args=2 } },
  { "pid",            { .min_args=0, .max_args=1 } },
  { "print",          { .min_args=1, .max_args=3 } },
  { "printf",         { .min_args=1, .max_args=128 } },
  { "pton",           { .min_args=1, .max_args=1 } },
  { "reg",            { .min_args=1, .max_args=1 } },
  { "sizeof",         { .min_args=1, .max_args=1 } },
  { "skboutput",      { .min_args=4, .max_args=4 } },
  { "socket_cookie",  { .min_args=1, .max_args=1 } },
  { "stack_len",      { .min_args=1, .max_args=1 } },
  { "stats",          { .min_args=3, .max_args=3 } },
  { "str",            { .min_args=1, .max_args=2 } },
  { "strftime",       { .min_args=2, .max_args=2 } },
  { "strncmp",        { .min_args=3, .max_args=3 } },
  { "sum",            { .min_args=3, .max_args=3 } },
  { "system",         { .min_args=1, .max_args=128 } },
  { "tid",            { .min_args=0, .max_args=1 } },
  { "time",           { .min_args=0, .max_args=1 } },
  { "tseries",        { .min_args=5, .max_args=6 } },
  { "unwatch",        { .min_args=1, .max_args=1 } },
  { "uptr",           { .min_args=1, .max_args=1 } },
  { "ustack",         { .min_args=0, .max_args=2 } },
  { "usym",           { .min_args=1, .max_args=1 } },
  { "warnf",          { .min_args=1, .max_args=128 } },
  { "zero",           { .min_args=1, .max_args=1 } },
};
// clang-format on

template <util::TypeName name>
class AssignMapDisallowed : public Visitor<AssignMapDisallowed<name>> {
public:
  explicit AssignMapDisallowed() = default;
  using Visitor<AssignMapDisallowed>::visit;
  void visit(AssignMapStatement &assignment)
  {
    assignment.addError() << "Map assignments not allowed inside of "
                          << name.str();
  }
};

class MapCheck : public Visitor<MapCheck> {
public:
  explicit MapCheck() = default;

  using Visitor<MapCheck>::visit;
  void visit(Offsetof &offof);
  void visit(Sizeof &szof);
  void visit(Typeof &typeof);
};

void MapCheck::visit(Offsetof &offof)
{
  AssignMapDisallowed<"offsetof">().visit(offof.record);
}

void MapCheck::visit(Sizeof &szof)
{
  AssignMapDisallowed<"sizeof">().visit(szof.record);
}

void MapCheck::visit(Typeof &typeof)
{
  AssignMapDisallowed<"typeof or typeinfo">().visit(typeof.record);
}

class CallPreCheck : public Visitor<CallPreCheck> {
public:
  explicit CallPreCheck(ASTContext &ctx, BPFtrace &bpftrace)
      : ctx_(ctx), bpftrace_(bpftrace)
  {
  }

  using Visitor<CallPreCheck>::visit;

  void visit(Call &call);
  void visit(Identifier &identifier);
  void visit(Probe &probe);
  void visit(String &string);
  void visit(Subprog &subprog);
  void visit(Unroll &unroll);

private:
  bool check_nargs(const Call &call, size_t expected_nargs);
  bool check_varargs(const Call &call, size_t min_nargs, size_t max_nargs);

  ASTContext &ctx_;
  BPFtrace &bpftrace_;
  std::string func_;
  int func_arg_idx_ = -1;
  Node *top_level_node_ = nullptr;
};

bool CallPreCheck::check_nargs(const Call &call, size_t expected_nargs)
{
  std::stringstream err;
  auto nargs = call.vargs.size();
  assert(nargs >= call.injected_args);
  assert(expected_nargs >= call.injected_args);
  nargs -= call.injected_args;
  expected_nargs -= call.injected_args;

  if (nargs != expected_nargs) {
    if (expected_nargs == 0)
      err << call.func << "() requires no arguments";
    else if (expected_nargs == 1)
      err << call.func << "() requires one argument";
    else
      err << call.func << "() requires " << expected_nargs << " arguments";

    err << " (" << nargs << " provided)";
    call.addError() << err.str();
    return false;
  }
  return true;
}

bool CallPreCheck::check_varargs(const Call &call,
                                 size_t min_nargs,
                                 size_t max_nargs)
{
  std::stringstream err;
  auto nargs = call.vargs.size();
  assert(nargs >= call.injected_args);
  assert(min_nargs >= call.injected_args);
  assert(max_nargs >= call.injected_args);
  nargs -= call.injected_args;
  min_nargs -= call.injected_args;
  max_nargs -= call.injected_args;

  if (nargs < min_nargs) {
    if (min_nargs == 1)
      err << call.func << "() requires at least one argument";
    else
      err << call.func << "() requires at least " << min_nargs << " arguments";

    err << " (" << nargs << " provided)";
    call.addError() << err.str();
    return false;
  } else if (nargs > max_nargs) {
    if (max_nargs == 0)
      err << call.func << "() requires no arguments";
    else if (max_nargs == 1)
      err << call.func << "() takes up to one argument";
    else
      err << call.func << "() takes up to " << max_nargs << " arguments";

    err << " (" << nargs << " provided)";
    call.addError() << err.str();
    return false;
  }

  return true;
}

void CallPreCheck::visit(Call &call)
{
  // Check for unsafe-ness first.
  if (bpftrace_.safe_mode_ && is_unsafe_func(call.func)) {
    call.addError() << call.func
                    << "() is an unsafe function being used in safe mode";
  }

  struct func_setter {
    func_setter(CallPreCheck &checker, const std::string &s)
        : checker_(checker), old_func_(checker_.func_)
    {
      checker_.func_ = s;
    }

    ~func_setter()
    {
      checker_.func_ = old_func_;
      checker_.func_arg_idx_ = -1;
    }

  private:
    CallPreCheck &checker_;
    std::string old_func_;
  };

  // Check probe availability
  if (auto *probe = dynamic_cast<Probe *>(top_level_node_)) {
    for (auto *ap : probe->attach_points) {
      if (!ap->check_available(call.func)) {
        call.addError() << call.func << " can not be used with \""
                        << ap->provider << "\" probes";
      }
    }
  }

  // Check argument count before visiting args to avoid cascading errors.
  auto spec = CALL_NARGS.find(call.func);
  if (spec != CALL_NARGS.end()) {
    bool nargs_ok;
    if (spec->second.min_args != spec->second.max_args) {
      nargs_ok = check_varargs(call,
                               spec->second.min_args,
                               spec->second.max_args);
    } else {
      nargs_ok = check_nargs(call, spec->second.min_args);
    }
    if (!nargs_ok) {
      return;
    }
  }

  func_setter scope_bound_func_setter{ *this, call.func };

  for (size_t i = 0; i < call.vargs.size(); ++i) {
    func_arg_idx_ = i;
    visit(call.vargs.at(i));
  }

  if (getRawMapArgFuncs().contains(call.func) && !call.vargs.empty()) {
    if (call.func != "print" && !call.vargs.at(0).is<Map>()) {
      call.vargs.at(0).node().addError()
          << call.func << "() expects a map argument";
    }
  }

  // Per-function literal/structural checks
  if (call.func == "hist") {
    if (call.vargs.size() == 4) {
      const auto *bits = call.vargs.at(3).as<Integer>();
      if (!bits) {
        LOG(BUG) << call.func << ": invalid bits value, need integer literal";
      } else if (bits->value > 5) {
        call.addError() << call.func << ": bits " << bits->value
                        << " must be 0..5";
      }
    }
  } else if (call.func == "lhist") {
    Expression &min_arg = call.vargs.at(3);
    Expression &max_arg = call.vargs.at(4);
    Expression &step_arg = call.vargs.at(5);
    auto *min = min_arg.as<Integer>();
    auto *max = max_arg.as<Integer>();
    auto *step = step_arg.as<Integer>();

    if (!min) {
      call.addError() << call.func
                      << ": invalid min value (must be non-negative literal)";
      return;
    }
    if (!max) {
      call.addError() << call.func
                      << ": invalid max value (must be non-negative literal)";
      return;
    }
    if (!step) {
      call.addError() << call.func << ": invalid step value";
      return;
    }

    if (step->value <= 0) {
      call.addError() << "lhist() step must be >= 1 (" << step->value
                      << " provided)";
    } else {
      int buckets = (max->value - min->value) / step->value;
      if (buckets > 1000) {
        call.addError()
            << "lhist() too many buckets, must be <= 1000 (would need "
            << buckets << ")";
      }
    }
    if (min->value > max->value) {
      call.addError() << "lhist() min must be less than max (provided min "
                      << min->value << " and max " << max->value << ")";
    }
    if ((max->value - min->value) < step->value) {
      call.addError()
          << "lhist() step is too large for the given range (provided step "
          << step->value << " for range " << (max->value - min->value) << ")";
    }
  } else if (call.func == "tseries") {
    const static std::set<std::string> ALLOWED_AGG_FUNCS = {
      "avg",
      "sum",
      "max",
      "min",
    };
    Expression &interval_ns_arg = call.vargs.at(3);
    Expression &num_intervals_arg = call.vargs.at(4);

    auto *interval_ns = interval_ns_arg.as<Integer>();
    auto *num_intervals = num_intervals_arg.as<Integer>();

    if (!interval_ns) {
      call.addError()
          << call.func
          << ": invalid interval_ns value (must be non-negative literal)";
      return;
    }
    if (!num_intervals) {
      call.addError()
          << call.func
          << ": invalid num_intervals value (must be non-negative literal)";
      return;
    }

    if (interval_ns->value <= 0) {
      call.addError() << "tseries() interval_ns must be >= 1 ("
                      << interval_ns->value << " provided)";
      return;
    }

    if (num_intervals->value <= 0) {
      call.addError() << "tseries() num_intervals must be >= 1 ("
                      << num_intervals->value << " provided)";
      return;
    } else if (num_intervals->value > 1000000) {
      call.addError() << "tseries() num_intervals must be < 1000000 ("
                      << num_intervals->value << " provided)";
    }

    if (call.vargs.size() == 6) {
      auto &aggregator = *call.vargs.at(5).as<String>();
      if (!ALLOWED_AGG_FUNCS.contains(aggregator.value)) {
        auto &err = call.addError();
        err << "tseries() expects one of the following aggregation "
               "functions: ";
        size_t i = 0;
        for (const std::string &agg : ALLOWED_AGG_FUNCS) {
          err << agg;
          if (i++ != ALLOWED_AGG_FUNCS.size() - 1) {
            err << ", ";
          }
        }
        err << " (\"" << aggregator.value << "\" provided)";
      }
    }
  } else if (call.func == "reg") {
    auto reg_name = call.vargs.at(0).as<String>()->value;
    auto offset = arch::Host::register_to_pt_regs_offset(reg_name);
    if (!offset) {
      call.addError() << "'" << reg_name
                      << "' is not a valid register on this architecture"
                      << " (" << arch::Host::Machine << ")";
    }
  } else if (call.func == "debugf") {
    call.addWarning()
        << "The debugf() builtin is not recommended for production use. "
           "For more information see bpf_trace_printk in bpf-helpers(7).";
    // bpf_trace_printk cannot use more than three arguments, see
    // bpf-helpers(7).
    constexpr int PRINTK_MAX_ARGS = 3;
    // args are all vargs after the format string
    auto num_args = call.vargs.size() - 1;
    if (num_args > static_cast<size_t>(PRINTK_MAX_ARGS)) {
      call.addError() << "cannot use more than " << PRINTK_MAX_ARGS
                      << " conversion specifiers";
    }
  } else if (call.func == "path") {
    if (call.vargs.size() == 2) {
      if (!call.vargs.at(1).is<Integer>()) {
        call.addError() << call.func
                        << ": invalid size value, need non-negative literal";
      }
    }

    if (auto *probe = dynamic_cast<Probe *>(top_level_node_)) {
      ProbeType type = probe->get_probetype();
      if (type != ProbeType::fentry && type != ProbeType::fexit &&
          type != ProbeType::iter) {
        call.addError() << "The path function can only be used with "
                        << "'fentry', 'fexit', 'iter' probes";
      }
    }
  } else if (call.func == "strncmp") {
    if (!call.vargs.at(2).is<Integer>()) {
      call.addError() << "Builtin strncmp requires a non-negative literal";
    }
  } else if (call.func == "pid" || call.func == "tid") {
    if (call.vargs.size() == 1) {
      auto &arg = call.vargs.at(0);
      if (!(arg.as<Identifier>())) {
        call.addError() << call.func
                        << "() only supports curr_ns and init as the argument";
      }
    }
  } else if (call.func == "__builtin_uaddr") {
    check_symbol(call);
  }
}

void CallPreCheck::visit(Identifier &identifier)
{
  if (func_ == "pid" || func_ == "tid") {
    if (identifier.ident != "curr_ns" && identifier.ident != "init") {
      identifier.addError()
          << "Invalid PID namespace mode: " << identifier.ident
          << " (expects: curr_ns or init)";
    }
  } else if (func_ == "signal") {
    if (identifier.ident != "current_pid" &&
        identifier.ident != "current_tid") {
      identifier.addError() << "Invalid signal target: " << identifier.ident
                            << " (expects: current_pid or current_tid)";
    }
  }
}

void CallPreCheck::visit(Probe &probe)
{
  top_level_node_ = &probe;
  Visitor<CallPreCheck>::visit(probe);
}

void CallPreCheck::visit(String &string)
{
  if ((func_ == "printf" || func_ == "errorf" || func_ == "warnf") &&
      func_arg_idx_ == 0)
    return;

  const auto str_len = bpftrace_.config_->max_strlen;
  if (!is_compile_time_func(func_) && string.value.size() > str_len - 1) {
    string.addError() << "String is too long (over " << str_len
                      << " bytes): " << string.value;
  }
}

void CallPreCheck::visit(Subprog &subprog)
{
  top_level_node_ = &subprog;
  Visitor<CallPreCheck>::visit(subprog);
}

void CallPreCheck::visit(Unroll &unroll)
{
  visit(unroll.expr);

  auto *integer = unroll.expr.as<Integer>();
  if (!integer) {
    unroll.addError() << "invalid unroll value";
    return;
  }

  if (integer->value > static_cast<uint64_t>(100)) {
    unroll.addError() << "unroll maximum value is 100";
  } else if (integer->value < static_cast<uint64_t>(1)) {
    unroll.addError() << "unroll minimum value is 1";
  }

  visit(unroll.block);
}

} // namespace

Pass CreatePreTypeCheckPass()
{
  return Pass::create("PreTypeCheck", [](ASTContext &ast, BPFtrace &bpftrace) {
    // Variable state is effectively reset for each probe and subprog
    for (auto &subprog : ast.root->functions) {
      VariablePreCheck().visit(subprog);
    }
    for (auto &probe : ast.root->probes) {
      VariablePreCheck().visit(probe);
    }

    MapCheck().visit(ast.root);

    CallPreCheck call_checker(ast, bpftrace);
    call_checker.visit(ast.root);
  });
}

} // namespace bpftrace::ast
