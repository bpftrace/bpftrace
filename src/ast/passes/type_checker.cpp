#include <algorithm>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <cstring>
#include <optional>
#include <regex>
#include <string>
#include <sys/stat.h>

#include "arch/arch.h"
#include "ast/ast.h"
#include "ast/async_event_types.h"
#include "ast/context.h"
#include "ast/helpers.h"
#include "ast/integer_types.h"
#include "ast/passes/fold_literals.h"
#include "ast/passes/macro_expansion.h"
#include "ast/passes/map_sugar.h"
#include "ast/passes/named_param.h"
#include "ast/passes/type_checker.h"
#include "ast/passes/type_system.h"
#include "bpftrace.h"
#include "btf/compat.h"
#include "collect_nodes.h"
#include "config.h"
#include "log.h"
#include "probe_matcher.h"
#include "probe_types.h"
#include "types.h"
#include "usdt.h"
#include "util/paths.h"
#include "util/strings.h"
#include "util/system.h"
#include "util/wildcard.h"

namespace bpftrace::ast {

namespace {

struct arg_type_spec {
  Type type = Type::integer;
  bool literal = false;

  // This indicates that this is just a placeholder as we use the index in the
  // vector of arg_type_spec as the number argument to check.
  bool skip_check = false;
};

struct call_spec {
  size_t min_args = 0;
  size_t max_args = 0;
  // NOLINTBEGIN(readability-redundant-member-init)
  std::vector<arg_type_spec> arg_types = {};
  // NOLINTEND(readability-redundant-member-init)
};

class TypeChecker : public Visitor<TypeChecker> {
public:
  explicit TypeChecker(ASTContext &ctx,
                       BPFtrace &bpftrace,
                       CDefinitions &c_definitions,
                       TypeMetadata &type_metadata,
                       bool has_child = true)
      : ctx_(ctx),
        bpftrace_(bpftrace),
        c_definitions_(c_definitions),
        type_metadata_(type_metadata),
        has_child_(has_child)
  {
  }

  using Visitor<TypeChecker>::visit;
  void visit(String &string);
  void visit(Identifier &identifier);
  void visit(Call &call);
  void visit(Sizeof &szof);
  void visit(Offsetof &offof);
  void visit(Typeof &typeof);
  void visit(Typeinfo &typeinfo);
  void visit(Map &map);
  void visit(MapAddr &map_addr);
  void visit(MapDeclStatement &decl);
  void visit(VariableAddr &var_addr);
  void visit(Binop &binop);
  void visit(Unop &unop);
  void visit(While &while_block);
  void visit(For &f);
  void visit(Jump &jump);
  void visit(IfExpr &if_expr);
  void visit(FieldAccess &acc);
  void visit(ArrayAccess &arr);
  void visit(TupleAccess &acc);
  void visit(MapAccess &acc);
  void visit(Cast &cast);
  void visit(Tuple &tuple);
  void visit(Expression &expr);
  void visit(ExprStatement &expr);
  void visit(AssignMapStatement &assignment);
  void visit(AssignVarStatement &assignment);
  void visit(VarDeclStatement &decl);
  void visit(Unroll &unroll);
  void visit(Probe &probe);
  void visit(BlockExpr &block);
  void visit(Subprog &subprog);

private:
  ASTContext &ctx_;
  BPFtrace &bpftrace_;
  CDefinitions &c_definitions_;
  TypeMetadata &type_metadata_;

  [[nodiscard]] bool check_arg(Call &call,
                               size_t index,
                               const arg_type_spec &spec);
  [[nodiscard]] bool check_call(Call &call);
  [[nodiscard]] bool check_nargs(const Call &call, size_t expected_nargs);
  [[nodiscard]] bool check_varargs(const Call &call,
                                   size_t min_nargs,
                                   size_t max_nargs);

  bool check_arg(Call &call,
                 Type type,
                 size_t index,
                 bool want_literal = false);

  Probe *get_probe();

  bool in_loop()
  {
    return loop_depth_ > 0;
  };

  Node *top_level_node_ = nullptr;

  // Holds the function currently being visited by this
  // TypeChecker.
  std::string func_;
  // Holds the function argument index currently being
  // visited by this TypeChecker.
  int func_arg_idx_ = -1;
  std::map<std::string, bpf_map_type> bpf_map_type_;

  uint32_t loop_depth_ = 0;
  bool has_child_ = false;
};

} // namespace

static const std::map<std::string, call_spec> CALL_SPEC = {
  { "avg",
    { .min_args = 3,
      .max_args = 3,
      .arg_types = { arg_type_spec{ .skip_check=true },
                     arg_type_spec{ .skip_check=true },
                     arg_type_spec{ .type = Type::integer } } } },
  { "bswap", { .min_args = 1, .max_args = 1 } },
  { "buf",
    { .min_args=1,
      .max_args=2,

      .arg_types={
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::integer } } } },
  { "cat",
    { .min_args=1,
      .max_args=128,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "cgroupid",
    { .min_args=1,
      .max_args=1,

      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "cgroup_path",
    { .min_args=1,
      .max_args=2,

      .arg_types={
        arg_type_spec{ .type=Type::integer },
        arg_type_spec{ .type=Type::string } } } },
  { "clear",
    { .min_args=1,
      .max_args=1,
      .arg_types={}
      } },
  { "count",
    { .min_args=2,
      .max_args=2,
      .arg_types={}
       } },
  { "debugf",
    { .min_args=1,
      .max_args=128,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "errorf",
    { .min_args=1,
      .max_args=128,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "exit",
    { .min_args=0,
      .max_args=1,
      .arg_types={
        arg_type_spec{ .type=Type::integer } } } },
  { "hist",
    { .min_args=3,
      .max_args=4,
      .arg_types={
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::integer },
        arg_type_spec{ .type=Type::integer, .literal=true } } } },
  { "join",
    { .min_args=1,
      .max_args=2,
      .arg_types={
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "kaddr",
    { .min_args=1,
      .max_args=1,

      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "kptr",
    { .min_args=1,
      .max_args=1,
       } },
  { "kstack",
    { .min_args=0,
      .max_args=2,
       } },
  { "ksym",
    { .min_args=1,
      .max_args=1,
       } },
  { "stack_len",
    { .min_args=1,
      .max_args=1,

    } },
  { "lhist",
    { .min_args=6,
      .max_args=6,
      .arg_types={
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::integer },
        arg_type_spec{ .type=Type::integer, .literal=true },
        arg_type_spec{ .type=Type::integer, .literal=true },
        arg_type_spec{ .type=Type::integer, .literal=true } } } },
  { "tseries",
    { .min_args=5,
      .max_args=6,
      .arg_types={
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::integer },
        arg_type_spec{ .type=Type::integer, .literal=true },
        arg_type_spec{ .type=Type::integer, .literal=true },
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "macaddr",
    { .min_args=1,
      .max_args=1,
       } },
  { "max",
    { .min_args=3,
      .max_args=3,
      .arg_types={
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::integer } } } },
  { "min",
    { .min_args=3,
      .max_args=3,
      .arg_types={
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::integer } } } },
  { "nsecs",
    { .min_args=0,
      .max_args=1,
      .arg_types={
        arg_type_spec{ .type=Type::timestamp_mode } } } },
  { "ntop",
    { .min_args=1,
      .max_args=2,
       } },
  { "offsetof",
    { .min_args=2,
      .max_args=2,
       } },
  { "path",
    { .min_args=1,
      .max_args=2,
      .arg_types={
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::integer, .literal=true } } } },
  { "percpu_kaddr",
    { .min_args=1,
      .max_args=2,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true },
        arg_type_spec{ .type=Type::integer } } } },
  { "print",
    { .min_args=1,
      .max_args=3,
      .arg_types={
        // This may be a pure map or not.
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::integer, .literal=true },
        arg_type_spec{ .type=Type::integer, .literal=true } } } },

  { "printf",
    { .min_args=1,
      .max_args=128,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "pton",
    { .min_args=1,
      .max_args=1,
       } },
  { "reg",
    { .min_args=1,
      .max_args=1,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "sizeof",
    { .min_args=1,
      .max_args=1,
       } },
  { "skboutput",
    { .min_args=4,
      .max_args=4,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true }, // pcap file name
        arg_type_spec{ .type=Type::pointer },      // *skb
        arg_type_spec{ .type=Type::integer },      // cap length
        // cap offset, default is 0
        // some tracepoints like dev_queue_xmit will output ethernet header,
        // set offset to 14 bytes can exclude this header
        arg_type_spec{ .type=Type::integer } } } },
  { "stats",
    { .min_args=3,
      .max_args=3,
      .arg_types={
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::integer } } } },
  { "str",
    { .min_args=1,
      .max_args=2,
      .arg_types={
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::integer } } } },
  { "strftime",
    { .min_args=2,
      .max_args=2,
      .arg_types={
          arg_type_spec{ .type=Type::string, .literal=true },
          arg_type_spec{ .type=Type::integer } } } },
  { "strncmp",
    { .min_args=3,
      .max_args=3,
      .arg_types={
          arg_type_spec{ .type=Type::string },
          arg_type_spec{ .type=Type::string },
          arg_type_spec{ .type=Type::integer, .literal=true } } } },
  { "sum",
    { .min_args=3,
      .max_args=3,
      .arg_types={
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .skip_check=true },
        arg_type_spec{ .type=Type::integer } } } },
  { "system",
    { .min_args=1,
      .max_args=128,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "time",
    { .min_args=0,
      .max_args=1,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "__builtin_uaddr",
    { .min_args=1,
      .max_args=1,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "unwatch",
    { .min_args=1,
      .max_args=1,
      .arg_types={
        arg_type_spec{ .type=Type::integer } } } },
  { "uptr",
    { .min_args=1,
      .max_args=1,
       } },
  { "ustack",
    { .min_args=0,
      .max_args=2,
       } },
  { "usym",
    { .min_args=1,
      .max_args=1,
       } },
  { "warnf",
    { .min_args=1,
      .max_args=128,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true } } } },
  { "zero",
    { .min_args=1,
      .max_args=1,
      .arg_types={} } },
  { "pid",
    { .min_args=0,
      .max_args=1 },
  },
  { "socket_cookie",
    { .min_args=1,
      .max_args=1,
      .arg_types={
        arg_type_spec{ .type=Type::pointer }, // struct sock *
      } } },
  { "fail",
    { .min_args=1,
      .max_args=128,
      .arg_types={
        arg_type_spec{ .type=Type::string, .literal=true },
      } } },
};
// clang-format on

// These are types which aren't valid for scratch variables
// e.g. this is not valid `let $x: sum_t;`
static bool IsValidVarDeclType(const SizedType &ty)
{
  switch (ty.GetTy()) {
    case Type::avg_t:
    case Type::count_t:
    case Type::hist_t:
    case Type::lhist_t:
    case Type::tseries_t:
    case Type::max_t:
    case Type::min_t:
    case Type::stats_t:
    case Type::sum_t:
    case Type::voidtype:
      return false;
    case Type::integer:
    case Type::kstack_t:
    case Type::ustack_t:
    case Type::timestamp:
    case Type::ksym_t:
    case Type::usym_t:
    case Type::inet:
    case Type::username:
    case Type::string:
    case Type::buffer:
    case Type::pointer:
    case Type::array:
    case Type::mac_address:
    case Type::c_struct:
    case Type::tuple:
    case Type::cgroup_path_t:
    case Type::none:
    case Type::timestamp_mode:
    case Type::boolean:
      return true;
  }
  return false; // unreachable
}

void TypeChecker::visit(String &string)
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

void TypeChecker::visit(Identifier &identifier)
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
  } else if (identifier.ident_type.IsNoneTy()) {
    identifier.addError() << "Unknown identifier: '" + identifier.ident + "'";
  }
}

void TypeChecker::visit(Call &call)
{
  // Check for unsafe-ness first. It is likely the most pertinent issue
  // (and should be at the top) for any function call.
  if (bpftrace_.safe_mode_ && is_unsafe_func(call.func)) {
    call.addError() << call.func
                    << "() is an unsafe function being used in safe mode";
  }

  struct func_setter {
    func_setter(TypeChecker &analyser, const std::string &s)
        : analyser_(analyser), old_func_(analyser_.func_)
    {
      analyser_.func_ = s;
    }

    ~func_setter()
    {
      analyser_.func_ = old_func_;
      analyser_.func_arg_idx_ = -1;
    }

  private:
    TypeChecker &analyser_;
    std::string old_func_;
  };

  func_setter scope_bound_func_setter{ *this, call.func };

  for (size_t i = 0; i < call.vargs.size(); ++i) {
    func_arg_idx_ = i;
    visit(call.vargs.at(i));
  }

  if (auto *probe = dynamic_cast<Probe *>(top_level_node_)) {
    for (auto *ap : probe->attach_points) {
      if (!ap->check_available(call.func)) {
        call.addError() << call.func << " can not be used with \""
                        << ap->provider << "\" probes";
      }
    }
  }

  if (!check_call(call)) {
    return;
  }

  if (call.func == "hist") {
    if (call.vargs.size() == 3) {
      call.vargs.emplace_back(ctx_.make_node<Integer>(call.loc, 0)); // default
                                                                     // bits is
                                                                     // 0
    } else {
      const auto *bits = call.vargs.at(3).as<Integer>();
      if (!bits) {
        // Bug here as the validity of the integer literal is already checked by
        // check_arg above.
        LOG(BUG) << call.func << ": invalid bits value, need integer literal";
      } else if (bits->value > 5) {
        call.addError() << call.func << ": bits " << bits->value
                        << " must be 0..5";
      }
    }

    call.return_type = CreateHist();
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

    call.return_type = CreateVoid();
  } else if (call.func == "str") {
    auto &arg = call.vargs.at(0);
    const auto &t = arg.type();
    if (!t.IsStringTy() && !t.IsIntegerTy() && !t.IsPtrTy()) {
      call.addError()
          << call.func
          << "() expects a string, integer or a pointer type as first "
          << "argument (" << t << " provided)";
    }
    auto strlen = bpftrace_.config_->max_strlen;
    if (call.vargs.size() == 2) {
      if (auto *integer = call.vargs.at(1).as<Integer>()) {
        if (integer->value + 1 > strlen) {
          call.addWarning() << "length param (" << integer->value
                            << ") is too long and will be shortened to "
                            << strlen << " bytes (see BPFTRACE_MAX_STRLEN)";
        } else {
          strlen = integer->value + 1; // Storage for NUL byte.
        }
      }

      if (auto *integer = dynamic_cast<NegativeInteger *>(
              call.vargs.at(1).as<NegativeInteger>())) {
        call.addError() << call.func << "cannot use negative length ("
                        << integer->value << ")";
      }
    }
    call.return_type = CreateString(strlen);
    call.return_type.SetAS(AddrSpace::kernel);
  } else if (call.func == "buf") {
    const uint64_t max_strlen = bpftrace_.config_->max_strlen;
    if (max_strlen >
        std::numeric_limits<decltype(AsyncEvent::Buf::length)>::max()) {
      call.addError() << "BPFTRACE_MAX_STRLEN too large to use on buffer ("
                      << max_strlen << " > "
                      << std::numeric_limits<uint32_t>::max() << ")";
    }

    auto &arg = call.vargs.at(0);
    if (!(arg.type().IsIntTy() || arg.type().IsStringTy() ||
          arg.type().IsPtrTy() || arg.type().IsArrayTy())) {
      call.addError()
          << call.func
          << "() expects an integer, string, or array argument but saw "
          << typestr(arg.type().GetTy());
    }

    if (call.vargs.size() == 1) {
      if (!arg.type().IsArrayTy()) {
        call.addError() << call.func
                        << "() expects a length argument for non-array type "
                        << typestr(arg.type().GetTy());
      }
    } else {
      if (auto *integer = call.vargs.at(1).as<NegativeInteger>()) {
        call.addError() << call.func << "cannot use negative length ("
                        << integer->value << ")";
      }
    }
  } else if (call.func == "ksym" || call.func == "usym") {
    // allow symbol lookups on casts (eg, function pointers)
    auto &arg = call.vargs.at(0);
    const auto &type = arg.type();
    if (!type.IsIntegerTy() && !type.IsPtrTy()) {
      call.addError() << call.func
                      << "() expects an integer or pointer argument";
    }
  } else if (call.func == "ntop") {
    int index = 0;
    if (call.vargs.size() == 2) {
      check_arg(call, Type::integer, 0);
      index = 1;
    }

    auto &arg = call.vargs.at(index);
    if (!arg.type().IsIntTy() && !arg.type().IsStringTy() &&
        !arg.type().IsArrayTy())
      call.addError() << call.func
                      << "() expects an integer or array argument, got "
                      << arg.type().GetTy();

    // Kind of:
    //
    // struct {
    //   int af_type;
    //   union {
    //     char[4] inet4;
    //     char[16] inet6;
    //   }
    // }
    auto type = arg.type();

    if ((arg.type().IsArrayTy() || arg.type().IsStringTy()) &&
        type.GetSize() != 4 && type.GetSize() != 16)
      call.addError() << call.func
                      << "() argument must be 4 or 16 bytes in size";
  } else if (call.func == "join") {
    auto &arg = call.vargs.at(0);
    if (!(arg.type().IsIntTy() || arg.type().IsPtrTy())) {
      call.addError() << "() only supports int or pointer arguments" << " ("
                      << arg.type().GetTy() << " provided)";
    }
  } else if (call.func == "reg") {
    auto reg_name = call.vargs.at(0).as<String>()->value;
    auto offset = arch::Host::register_to_pt_regs_offset(reg_name);
    if (!offset) {
      call.addError() << "'" << reg_name
                      << "' is not a valid register on this architecture"
                      << " (" << arch::Host::Machine << ")";
    }
  } else if (call.func == "percpu_kaddr") {
    const auto &symbol = call.vargs.at(0).as<String>()->value;
    if (bpftrace_.btf_->get_var_type(symbol).IsNoneTy()) {
      call.addError() << "Could not resolve variable \"" << symbol
                      << "\" from BTF";
    }
  } else if (call.func == "printf" || call.func == "errorf" ||
             call.func == "warnf" || call.func == "system" ||
             call.func == "cat" || call.func == "debugf") {
    const auto &fmt = call.vargs.at(0).as<String>()->value;
    std::vector<SizedType> args;
    for (size_t i = 1; i < call.vargs.size(); i++) {
      args.push_back(call.vargs[i].type());
    }
    FormatString fs(fmt);
    auto ok = fs.check(args);
    if (!ok) {
      call.addError() << ok.takeError();
    }
    // The `debugf` call is a builtin, and is subject to more much rigorous
    // checks. We've already validate the basic counts, etc. but we need to
    // apply these additional constraints which includes a limited surface.
    if (call.func == "debugf") {
      call.addWarning()
          << "The debugf() builtin is not recommended for production use. "
             "For more information see bpf_trace_printk in bpf-helpers(7).";
      // bpf_trace_printk cannot use more than three arguments, see
      // bpf-helpers(7).
      constexpr int PRINTK_MAX_ARGS = 3;
      if (args.size() > PRINTK_MAX_ARGS) {
        call.addError() << "cannot use more than " << PRINTK_MAX_ARGS
                        << " conversion specifiers";
      }
      for (size_t i = 0; i < args.size(); i++) {
        // bpf_trace_printk_format_types is a subset of printf_format_types
        // that contains valid types for bpf_trace_printk() see iovisor/bcc
        // BTypeVisitor::checkFormatSpecifiers.
        static const std::unordered_map<std::string, Type>
            bpf_trace_printk_format_types = { { "d", Type::integer },
                                              { "u", Type::integer },
                                              { "x", Type::integer },
                                              { "p", Type::integer },
                                              { "s", Type::string } };
        auto it = bpf_trace_printk_format_types.find(fs.specs[i].specifier);
        if (it == bpf_trace_printk_format_types.end()) {
          call.vargs.at(0).node().addError()
              << "Invalid format specifier for `debugf`: "
              << fs.specs[i].specifier;
          continue;
        }
        if (args[i].GetTy() != it->second) {
          call.vargs.at(i + 1).node().addError()
              << "Type does not match format specifier: "
              << fs.specs[i].specifier;
          continue;
        }
      }
    }
  }
  if (call.func == "print") {
    if (auto *map = call.vargs.at(0).as<Map>()) {
      // N.B. that print is parameteric in the type, so this is not checked
      // by `check_arg` as there is no spec for the first argument.
      if (map->type().IsNoneTy()) {
        map->addError() << "Undefined map: " + map->ident;
      } else {
        if (in_loop()) {
          call.addWarning() << "Due to it's asynchronous nature using "
                               "'print()' in a loop can "
                               "lead to unexpected behavior. The map will "
                               "likely be updated "
                               "before the runtime can 'print' it.";
        }
        if (map->value_type.IsStatsTy() && call.vargs.size() > 1) {
          call.addWarning()
              << "print()'s top and div arguments are ignored when used on "
                 "stats() maps.";
        }
      }
    }
    // Note that IsPrintableTy() is somewhat disingenuous here. Printing a
    // non-map value requires being able to serialize the entire value, so
    // map-backed types like count(), min(), max(), etc. cannot be printed
    // through the non-map printing mechanism.
    //
    // We rely on the fact that semantic analysis enforces types like count(),
    // min(), max(), etc. to be assigned directly to a map.
    else if (call.vargs.at(0).type().IsMultiKeyMapTy()) {
      call.addError()
          << "Map type " << call.vargs.at(0).type()
          << " cannot print the value of individual keys. You must print "
             "the whole map.";
    } else if (call.vargs.at(0).type().IsPrintableTy()) {
      if (call.vargs.size() != 1)
        call.addError() << "Non-map print() only takes 1 argument, "
                        << call.vargs.size() << " found";
    } else {
      call.addError() << call.vargs.at(0).type() << " type passed to "
                      << call.func << "() is not printable";
    }
  } else if (call.func == "stack_len") {
    if (!call.vargs.at(0).type().IsStack()) {
      call.addError() << "len() expects a map or stack to be provided";
    }
  } else if (call.func == "strftime") {
    auto &arg = call.vargs.at(1);
    call.return_type.ts_mode = arg.type().ts_mode;
    if (call.return_type.ts_mode == TimestampMode::monotonic) {
      call.addError() << "strftime() can not take a monotonic timestamp";
    }
  } else if (call.func == "path") {
    auto *probe = get_probe();
    if (probe == nullptr)
      return;

    if (!bpftrace_.feature_->has_d_path()) {
      call.addError()
          << "BPF_FUNC_d_path not available for your kernel version";
    }

    // Argument for path can be both record and pointer.
    // It's pointer when it's passed directly from the probe
    // argument, like: path(args.path))
    // It's record when it's referenced as object pointer
    // member, like: path(args.filp->f_path))
    auto &arg = call.vargs.at(0);
    if (arg.type().GetTy() != Type::c_struct &&
        arg.type().GetTy() != Type::pointer) {
      call.addError() << "path() only supports pointer or record argument ("
                      << arg.type().GetTy() << " provided)";
    }

    if (call.vargs.size() == 2) {
      if (!call.vargs.at(1).is<Integer>()) {
        call.addError() << call.func
                        << ": invalid size value, need non-negative literal";
      }
    }

    ProbeType type = probe->get_probetype();
    if (type != ProbeType::fentry && type != ProbeType::fexit &&
        type != ProbeType::iter) {
      call.addError() << "The path function can only be used with "
                      << "'fentry', 'fexit', 'iter' probes";
    }
  } else if (call.func == "strncmp") {
    if (!call.vargs.at(2).is<Integer>()) {
      call.addError() << "Builtin strncmp requires a non-negative literal";
    }
  } else if (call.func == "kptr" || call.func == "uptr") {
    // kptr should accept both integer or pointer. Consider case: kptr($1)
    auto &arg = call.vargs.at(0);
    if (!arg.type().IsIntTy() && !arg.type().IsPtrTy()) {
      call.addError() << call.func << "() only supports "
                      << "integer or pointer arguments (" << arg.type().GetTy()
                      << " provided)";
      return;
    }
  } else if (call.func == "macaddr") {
    auto &arg = call.vargs.at(0);
    if (!arg.type().IsIntTy() && !arg.type().IsArrayTy() &&
        !arg.type().IsByteArray() && !arg.type().IsPtrTy())
      call.addError() << call.func
                      << "() only supports array or pointer arguments" << " ("
                      << arg.type().GetTy() << " provided)";

    if (arg.is<String>())
      call.addError() << call.func
                      << "() does not support literal string arguments";

    // N.B. When converting from BTF, we can treat string types as 7 bytes in
    // order to signal to userspace that they are well-formed. However, we can
    // convert from anything as long as there are at least 6 bytes to read.
    const auto &type = arg.type();
    if ((type.IsArrayTy() || type.IsByteArray()) && type.GetSize() < 6) {
      call.addError() << call.func
                      << "() argument must be at least 6 bytes in size";
    }
  } else if (call.func == "nsecs") {
    if (call.return_type.ts_mode == TimestampMode::tai &&
        !bpftrace_.feature_->has_helper_ktime_get_tai_ns()) {
      call.addError()
          << "Kernel does not support tai timestamp, please try sw_tai";
    }
    if (call.return_type.ts_mode == TimestampMode::sw_tai &&
        !bpftrace_.delta_taitime_.has_value()) {
      call.addError() << "Failed to initialize sw_tai in "
                         "userspace. This is very unexpected.";
    }
  } else if (call.func == "pid" || call.func == "tid") {
    if (call.vargs.size() == 1) {
      auto &arg = call.vargs.at(0);
      if (!(arg.as<Identifier>())) {
        call.addError() << call.func
                        << "() only supports curr_ns and init as the argument ("
                        << arg.type().GetTy() << " provided)";
      }
    }
  } else if (call.func == "socket_cookie") {
    auto logError = [&]<typename T>(T name) {
      call.addError() << call.func
                      << "() only supports 'struct sock *' as the argument ("
                      << name << " provided)";
    };

    const auto &type = call.vargs.at(0).type();
    if (!type.IsPtrTy() || !type.GetPointeeTy() ||
        !type.GetPointeeTy()->IsCStructTy()) {
      logError(type.GetTy());
      return;
    }
    if (!type.GetPointeeTy()->IsCompatible(CreateCStruct("struct sock"))) {
      logError("'" + type.GetPointeeTy()->GetName() + " *'");
      return;
    }
  } else if (call.func == "fail") {
    // This is basically a static_assert failure. It will halt the compilation.
    // We expect to hit this path only when using the `typeof` folds.
    bool fail_valid = true;
    std::vector<output::Primitive> args;
    for (size_t i = 0; i < call.vargs.size(); ++i) {
      if (!call.vargs[i].is_literal()) {
        fail_valid = false;
        call.addError() << "fail() arguments need to be literals";
      } else {
        if (i != 0) {
          if (auto *val = call.vargs[i].as<String>()) {
            args.emplace_back(val->value);
          } else if (auto *val = call.vargs[i].as<Integer>()) {
            args.emplace_back(val->value);
          } else if (auto *val = call.vargs[i].as<NegativeInteger>()) {
            args.emplace_back(val->value);
          } else if (auto *val = call.vargs[i].as<Boolean>()) {
            args.emplace_back(val->value);
          }
        } else {
          if (!call.vargs[0].is<String>()) {
            call.addError()
                << "first argument to fail() must be a string literal";
          }
        }
      }
    }

    if (fail_valid) {
      FormatString fs(call.vargs[0].as<String>()->value);
      call.addError() << fs.format(args);
    }
  } else if (call.func == "exit") {
    // OK
  } else {
    // Check here if this corresponds to an external function. We convert the
    // external type metadata into the internal `SizedType` representation and
    // check that they are exactly equal.
    auto maybe_func = type_metadata_.global.lookup<btf::Function>(call.func);
    if (!maybe_func) {
      if (call.return_type.IsNoneTy()) {
        LOG(BUG) << "Unknown builtin function " << call.func;
      }
      return;
    }

    const auto &func = *maybe_func;
    auto proto = func.type();
    if (!proto) {
      return;
    }

    // Convert all arguments.
    auto argument_types = proto->argument_types();
    if (!argument_types) {
      call.addError() << "Unable to read argument types: "
                      << argument_types.takeError();
      return;
    }
    // Check the argument count.
    if (argument_types->size() != call.vargs.size()) {
      call.addError() << "Function `" << call.func << "` requires "
                      << argument_types->size() << " arguments, got only "
                      << call.vargs.size();
      return;
    }
    std::vector<std::pair<std::string, SizedType>> args;
    for (size_t i = 0; i < argument_types->size(); i++) {
      const auto &[name, type] = argument_types->at(i);
      auto compat_arg_type = getCompatType(type);
      if (!compat_arg_type) {
        // If the required type is a **pointer**, and the provided type is
        // a **pointer**, then we let it slide. Just assume the user knows
        // what they are doing. The verifier will catch them out otherwise.
        if (type.is<btf::Pointer>() && call.vargs[i].type().IsPtrTy()) {
          args.emplace_back(name, call.vargs[i].type());
          continue;
        }
        call.addError() << "Unable to convert argument type, "
                        << "function requires '" << type << "', " << "found '"
                        << typestr(call.vargs[i].type())
                        << "': " << compat_arg_type.takeError();
        continue;
      }
      args.emplace_back(name, std::move(*compat_arg_type));
    }
    if (args.size() != argument_types->size()) {
      return; // Already emitted errors.
    }
    // Check all the individual arguments.
    bool ok = true;
    for (size_t i = 0; i < args.size(); i++) {
      const auto &[name, type] = args[i];
      if (type != call.vargs[i].type()) {
        if (!name.empty()) {
          call.vargs[i].node().addError()
              << "Expected " << typestr(type) << " for argument `" << name
              << "` got " << typestr(call.vargs[i].type());
        } else {
          call.vargs[i].node().addError()
              << "Expected " << typestr(type) << " got "
              << typestr(call.vargs[i].type());
        }
        ok = false;
      }
    }
    // Build our full proto as an error message.
    std::stringstream fullmsg;
    fullmsg << "Function `" << call.func << "` requires arguments (";
    bool first = true;
    for (const auto &[name, type] : args) {
      if (!first) {
        fullmsg << ", ";
      }
      fullmsg << typestr(type);
      first = false;
    }
    fullmsg << ")";
    if (!ok) {
      call.addError() << fullmsg.str();
      return;
    }
  }
}

void TypeChecker::visit(Sizeof &szof)
{
  visit(szof.record);
}

void TypeChecker::visit(Offsetof &offof)
{
  visit(offof.record);
}

void TypeChecker::visit(Typeof &typeof)
{
  visit(typeof.record);
}

void TypeChecker::visit(Typeinfo &typeinfo)
{
  Visitor<TypeChecker>::visit(typeinfo);
}

Probe *TypeChecker::get_probe()
{
  auto *probe = dynamic_cast<Probe *>(top_level_node_);
  return probe;
}

void TypeChecker::visit(MapDeclStatement &decl)
{
  const auto bpf_type = get_bpf_map_type(decl.bpf_type);
  if (!bpf_type) {
    auto &err = decl.addError();
    err << "Invalid bpf map type: " << decl.bpf_type;
    auto &hint = err.addHint();
    add_bpf_map_types_hint(hint);
  } else {
    bpf_map_type_.insert({ decl.ident, *bpf_type });
  }
}

void TypeChecker::visit(Map &map)
{
  // Note that the naked `Map` node actually gets no type, the type
  // is applied to the node at the `MapAccess` level.
  auto found_kind = bpf_map_type_.find(map.ident);
  if (found_kind != bpf_map_type_.end()) {
    if (!bpf_map_types_compatible(map.value_type, found_kind->second)) {
      auto map_type = get_bpf_map_type(map.value_type);
      map.addError() << "Incompatible map types. Type from declaration: "
                     << get_bpf_map_type_str(found_kind->second)
                     << ". Type from value/key type: "
                     << get_bpf_map_type_str(map_type);
    }
  }
}
void TypeChecker::visit(MapAddr &map_addr)
{
  visit(map_addr.map);
}

void TypeChecker::visit(VariableAddr &var_addr)
{
  if (var_addr.var_addr_type.IsNoneTy()) {
    var_addr.addError() << "No type available for variable "
                        << var_addr.var->ident;
  }
}

void TypeChecker::visit(ArrayAccess &arr)
{
  visit(arr.expr);
  visit(arr.indexpr);

  const SizedType &type = arr.expr.type();

  if (!type.IsArrayTy() && !type.IsPtrTy() && !type.IsStringTy()) {
    arr.addError() << "The array index operator [] can only be "
                      "used on arrays and pointers, found "
                   << type.GetTy() << ".";
    return;
  }

  if (type.IsPtrTy() && type.GetPointeeTy()->GetSize() == 0) {
    arr.addError() << "The array index operator [] cannot be used "
                      "on a pointer to an unsized type (void *).";
  }

  if (auto *integer = arr.indexpr.as<Integer>()) {
    auto num = [&]() -> size_t {
      if (type.IsArrayTy()) {
        return type.GetNumElements();
      } else if (type.IsStringTy()) {
        return type.GetSize();
      } else {
        return 0;
      }
    }();
    if (num != 0 && static_cast<size_t>(integer->value) >= num) {
      arr.addError() << "the index " << integer->value
                     << " is out of bounds for array of size " << num;
    }
  } else if (!arr.indexpr.type().IsIntTy() || arr.indexpr.type().IsSigned()) {
    arr.addError() << "The array index operator [] only "
                      "accepts positive (unsigned) integer indices. Got: "
                   << arr.indexpr.type();
  }
}

void TypeChecker::visit(TupleAccess &acc)
{
  visit(acc.expr);
  const SizedType &type = acc.expr.type();

  if (!type.IsTupleTy()) {
    acc.addError() << "Can not access index '" << acc.index
                   << "' on expression of type '" << type << "'";
    return;
  }

  if (acc.index >= type.GetFields().size()) {
    acc.addError() << "Invalid tuple index: " << acc.index << ". Found "
                   << type.GetFields().size() << " elements in tuple.";
  }
}

void TypeChecker::visit(Binop &binop)
{
  visit(binop.left);
  visit(binop.right);

  const auto &lht = binop.left.type();
  const auto &rht = binop.right.type();
  bool is_int_binop = (lht.IsCastableMapTy() || lht.IsIntTy() ||
                       lht.IsBoolTy()) &&
                      (rht.IsCastableMapTy() || rht.IsIntTy() ||
                       rht.IsBoolTy());
  bool is_ptr_binop = lht.IsPtrTy() || rht.IsPtrTy();
  bool is_array_binop = lht.IsArrayTy() && rht.IsArrayTy();

  if (is_int_binop || is_ptr_binop) {
    // Already handled in a previous pass
  } else if (is_array_binop) {
    if (binop.op != Operator::EQ && binop.op != Operator::NE) {
      binop.addError() << "The " << opstr(binop)
                       << " operator cannot be used on arrays.";
    }

    if (lht.GetNumElements() != rht.GetNumElements()) {
      binop.addError()
          << "Only arrays of same size support comparison operators.";
    }

    if (!lht.GetElementTy()->IsIntegerTy() || lht != rht) {
      binop.addError()
          << "Only arrays of same sized integer support comparison operators.";
    }
  } else if (!lht.IsCompatible(rht)) {
    auto &err = binop.addError();
    err << "Type mismatch for '" << opstr(binop) << "': comparing " << lht
        << " with " << rht;
    err.addContext(binop.left.loc()) << "left (" << lht << ")";
    err.addContext(binop.right.loc()) << "right (" << rht << ")";
  }
  // Also allow combination like reg("sp") + 8
  else if (binop.op != Operator::EQ && binop.op != Operator::NE) {
    binop.addError() << "The " << opstr(binop)
                     << " operator can not be used on expressions of types "
                     << lht << ", " << rht;
  }
}

void TypeChecker::visit(Unop &unop)
{
  if (unop.op == Operator::PRE_INCREMENT ||
      unop.op == Operator::PRE_DECREMENT ||
      unop.op == Operator::POST_INCREMENT ||
      unop.op == Operator::POST_DECREMENT) {
    if (!unop.expr.is<Variable>() && !unop.expr.is<MapAccess>()) {
      unop.addError() << "The " << opstr(unop)
                      << " operator must be applied to a map or variable";
    }
  }

  visit(unop.expr);

  auto valid_ptr_op = false;
  switch (unop.op) {
    case Operator::PRE_INCREMENT:
    case Operator::PRE_DECREMENT:
    case Operator::POST_INCREMENT:
    case Operator::POST_DECREMENT:
    case Operator::MUL:
      valid_ptr_op = true;
      break;
    default:;
  }

  const SizedType &type = unop.expr.type();
  bool invalid = false;
  // Unops are only allowed on ints (e.g. ~$x), dereference only on pointers
  // and context (we allow args->field for backwards compatibility)
  if (type.IsBoolTy()) {
    invalid = unop.op != Operator::LNOT;
  } else if (!type.IsIntegerTy() &&
             !((type.IsPtrTy() || type.IsCtxAccess()) && valid_ptr_op)) {
    invalid = true;
  }
  if (invalid) {
    unop.addError() << "The " << opstr(unop)
                    << " operator can not be used on expressions of type '"
                    << type << "'";
  }
}

void TypeChecker::visit(IfExpr &if_expr)
{
  visit(if_expr.cond);
  visit(if_expr.left);
  visit(if_expr.right);
}

void TypeChecker::visit(Unroll &unroll)
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

void TypeChecker::visit(Jump &jump)
{
  if (jump.ident == JumpType::RETURN) {
    visit(jump.return_value);
    if (dynamic_cast<Probe *>(top_level_node_)) {
      if (jump.return_value.has_value()) {
        const auto &ty = jump.return_value->type();
        if (!ty.IsIntegerTy()) {
          jump.addError() << "Probe return values can only be integers. Found "
                          << ty;
        }
      }
    }
  }
}

void TypeChecker::visit(While &while_block)
{
  visit(while_block.cond);

  loop_depth_++;
  visit(while_block.block);
  loop_depth_--;
}

void TypeChecker::visit(For &f)
{
  if (f.iterable.is<Range>() && !bpftrace_.feature_->has_helper_loop()) {
    f.addError() << "Missing required kernel feature: loop";
  }

  visit(f.iterable);
  loop_depth_++;
  visit(f.block);

  if (auto *range = f.iterable.as<Range>()) {
    if (!range->start.type().IsIntTy()) {
      range->addError() << "Loop range requires an integer for the start value";
    }
    if (!range->end.type().IsIntTy()) {
      range->addError() << "Loop range requires an integer for the end value";
    }
  }

  // Currently, we do not pass BPF context to the callback so disable builtins
  // which require ctx access.
  CollectNodes<Builtin> builtins;
  builtins.visit(f.block);
  for (const Builtin &builtin : builtins.nodes()) {
    if (builtin.builtin_type.IsCtxAccess()) {
      builtin.addError() << "'" << builtin.ident
                         << "' builtin is not allowed in a for-loop";
    }
  }

  loop_depth_--;
}

void TypeChecker::visit(FieldAccess &acc)
{
  visit(acc.expr);

  // FieldAccesses will automatically resolve through any number of pointer
  // dereferences. For now, we inject the `Unop` operator directly, as codegen
  // stores the underlying structs as pointers anyways. In the future, we will
  // likely want to do this in a different way if we are tracking l-values.
  while (acc.expr.type().IsPtrTy()) {
    auto *unop = ctx_.make_node<Unop>(acc.expr.node().loc,
                                      acc.expr,
                                      Operator::MUL);
    acc.expr.value = unop;
    visit(acc.expr);
  }

  const SizedType &type = acc.expr.type();

  if (type.IsPtrTy()) {
    acc.addError() << "Can not access field '" << acc.field << "' on type '"
                   << type << "'. Try dereferencing it first, or using '->'";
    return;
  }

  if (!type.IsCStructTy()) {
    acc.addError() << "Can not access field '" << acc.field
                   << "' on expression of type '" << type << "'";
    return;
  }

  if (type.is_funcarg) {
    auto *probe = get_probe();
    if (probe == nullptr)
      return;
    const auto *arg = bpftrace_.structs.GetProbeArg(*probe, acc.field);
    if (arg) {
      acc.field_type = arg->type;
      acc.field_type.SetAS(acc.expr.type().GetAS());

      if (acc.field_type.IsNoneTy()) {
        acc.addError() << acc.field << " has unsupported type";
      }
    } else {
      acc.addError() << "Can't find function parameter " << acc.field;
    }
    return;
  }

  if (!bpftrace_.structs.Has(type.GetName())) {
    acc.addError() << "Unknown struct/union: '" << type.GetName() << "'";
    return;
  }

  std::string cast_type = type.GetName();
  const auto &record = type.GetStruct();

  if (!record->HasField(acc.field)) {
    acc.addError() << "Struct/union of type '" << cast_type
                   << "' does not contain " << "a field named '" << acc.field
                   << "'";
  } else {
    const auto &field = record->GetField(acc.field);

    if (field.type.IsPtrTy()) {
      const auto &tags = field.type.GetBtfTypeTags();
      // Currently only "rcu" is safe. "percpu", for example, requires
      // special unwrapping with `bpf_per_cpu_ptr` which is not yet
      // supported.
      static const std::string_view allowed_tag = "rcu";
      for (const auto &tag : tags) {
        if (tag != allowed_tag) {
          acc.addError() << "Attempting to access pointer field '" << acc.field
                         << "' with unsupported tag attribute: " << tag;
        }
      }
    }

    acc.field_type = field.type;
    if (acc.expr.type().IsCtxAccess() &&
        (acc.field_type.IsArrayTy() || acc.field_type.IsCStructTy())) {
      // e.g., ((struct bpf_perf_event_data*)ctx)->regs.ax
      acc.field_type.MarkCtxAccess();
    }
    acc.field_type.is_internal = type.is_internal;
    acc.field_type.SetAS(acc.expr.type().GetAS());

    // The kernel uses the first 8 bytes to store `struct pt_regs`. Any
    // access to the first 8 bytes results in verifier error.
    if (record->is_tracepoint_args && field.offset < 8)
      acc.addError()
          << "BPF does not support accessing common tracepoint fields";
  }
}

void TypeChecker::visit(MapAccess &acc)
{
  visit(acc.map);
  visit(acc.key);

  if (acc.map->type().IsCastableMapTy() &&
      !bpftrace_.feature_->has_helper_map_lookup_percpu_elem()) {
    acc.addError() << "Missing required kernel feature: map_lookup_percpu_elem";
  }

  // Validate map key type
  const auto &key_type = acc.key.type();
  if (key_type.IsPtrTy() && key_type.IsCtxAccess()) {
    // map functions only accepts a pointer to a element in the stack
    acc.key.node().addError() << "context cannot be part of a map key";
  }

  if (key_type.IsHistTy() || key_type.IsLhistTy() || key_type.IsStatsTy() ||
      key_type.IsTSeriesTy()) {
    acc.key.node().addError() << key_type << " cannot be part of a map key";
  }

  if (key_type.IsNoneTy() || key_type.IsVoidTy()) {
    acc.key.node().addError() << "Invalid map key type: " << key_type;
  }

  // For tuple keys, validate each element
  if (key_type.IsTupleTy()) {
    for (const auto &field : key_type.GetFields()) {
      if (field.type.IsPtrTy() && field.type.IsCtxAccess()) {
        acc.key.node().addError() << "context cannot be part of a map key";
      }
      if (field.type.IsHistTy() || field.type.IsLhistTy() ||
          field.type.IsStatsTy() || field.type.IsTSeriesTy()) {
        acc.key.node().addError()
            << field.type << " cannot be part of a map key";
      }
    }
  }
}

void TypeChecker::visit(Cast &cast)
{
  visit(cast.expr);
  visit(cast.typeof);

  const auto &resolved_ty = cast.type();
  if (resolved_ty.IsNoneTy()) {
    cast.addError() << "Incomplete cast, unknown type";
    return;
  }

  auto rhs = cast.expr.type();
  if (rhs.IsCStructTy()) {
    cast.addError() << "Cannot cast from struct type \"" << cast.expr.type()
                    << "\"";
    return;
  } else if (rhs.IsNoneTy()) {
    cast.addError() << "Cannot cast from \"" << cast.expr.type() << "\" type";
    return;
  }

  // Resolved the type because we may mutate it below, for various reasons.
  cast.typeof->record = resolved_ty;
  auto &ty = std::get<SizedType>(cast.typeof->record);

  auto logError = [&]() {
    cast.addError() << "Cannot cast from \"" << rhs << "\" to \"" << ty << "\"";
  };

  if (ty.IsStringTy() && rhs.IsStringTy()) {
    if (ty.GetSize() < rhs.GetSize()) {
      logError();
    }
    return;
  }

  if (!ty.IsIntTy() && !ty.IsPtrTy() && !ty.IsBoolTy() &&
      (!ty.IsPtrTy() || ty.GetElementTy()->IsIntTy() ||
       ty.GetElementTy()->IsCStructTy()) &&
      // we support casting integers to int arrays
      !(ty.IsArrayTy() && ty.GetElementTy()->IsBoolTy()) &&
      !(ty.IsArrayTy() && ty.GetElementTy()->IsIntTy())) {
    logError();
  }

  if (ty.IsArrayTy()) {
    if (ty.GetNumElements() == 0) {
      if (ty.GetElementTy()->GetSize() == 0)
        cast.addError() << "Could not determine size of the array";
      else {
        if (rhs.GetSize() % ty.GetElementTy()->GetSize() != 0) {
          cast.addError() << "Cannot determine array size: the element size is "
                             "incompatible with the cast integer size";
        }
      }
    }

    if (rhs.IsIntTy()) {
      if ((ty.GetElementTy()->IsIntegerTy() || ty.GetElementTy()->IsBoolTy())) {
        if ((ty.GetSize() <= 8) && (ty.GetSize() > rhs.GetSize())) {
          // ok
        } else if (ty.GetSize() != rhs.GetSize()) {
          logError();
        }
      }
    } else {
      if ((!rhs.IsBoolTy() && !rhs.IsStringTy()) ||
          ty.GetSize() != rhs.GetSize()) {
        logError();
      }
    }
  }

  if (ty.IsEnumTy()) {
    if (!c_definitions_.enum_defs.contains(ty.GetName())) {
      cast.addError() << "Unknown enum: " << ty.GetName();
    } else {
      if (auto *integer = cast.expr.as<Integer>()) {
        if (!c_definitions_.enum_defs[ty.GetName()].contains(integer->value)) {
          cast.addError() << "Enum: " << ty.GetName()
                          << " doesn't contain a variant value of "
                          << integer->value;
        }
      }
    }
  }

  if (!rhs.IsPtrTy() && !rhs.IsCastableMapTy() && !rhs.IsIntTy()) {
    if (ty.IsBoolTy() && !rhs.IsStringTy()) {
      logError();
    }

    if (ty.IsIntTy() && !rhs.IsBoolTy() && !rhs.IsCtxAccess() &&
        !rhs.IsArrayTy()) {
      logError();
    }
  }

  if ((rhs.IsArrayTy() && (!ty.IsIntTy() || ty.GetSize() != rhs.GetSize()))) {
    logError();
  }
}

void TypeChecker::visit(Tuple &tuple)
{
  for (auto &elem : tuple.elems) {
    visit(elem);

    // If elem type is none that means that the tuple is not yet resolved.
    if (elem.type().IsMultiKeyMapTy()) {
      elem.node().addError()
          << "Map type " << elem.type() << " cannot exist inside a tuple.";
    }
  }
}

void TypeChecker::visit(Expression &expr)
{
  Visitor<TypeChecker>::visit(expr);
}

void TypeChecker::visit(ExprStatement &expr)
{
  visit(expr.expr);

  if (!(expr.expr.type().IsNoneTy() || expr.expr.type().IsVoidTy())) {
    expr.addWarning() << "Return value discarded.";
  }
}

static const std::unordered_map<Type, std::string_view> AGGREGATE_HINTS{
  { Type::count_t, "count()" },
  { Type::sum_t, "sum(retval)" },
  { Type::min_t, "min(retval)" },
  { Type::max_t, "max(retval)" },
  { Type::avg_t, "avg(retval)" },
  { Type::hist_t, "hist(retval)" },
  { Type::lhist_t, "lhist(rand %10, 0, 10, 1)" },
  { Type::tseries_t, "tseries(rand %10, 10s, 1)" },
  { Type::stats_t, "stats(arg2)" },
};

void TypeChecker::visit(AssignMapStatement &assignment)
{
  visit(assignment.map_access);
  visit(assignment.expr);
}

void TypeChecker::visit(AssignVarStatement &assignment)
{
  visit(assignment.expr);

  // Only visit the declaration if it is a `let` declaration,
  // otherwise skip as it is not a variable access.
  if (std::holds_alternative<VarDeclStatement *>(assignment.var_decl)) {
    visit(assignment.var_decl);
  }

  if (assignment.var()->var_type.IsNoneTy()) {
    assignment.addError() << "Invalid expression for assignment";
  }
}

void TypeChecker::visit(VarDeclStatement &decl)
{
  visit(decl.typeof);

  if (decl.typeof) {
    const auto &ty = decl.typeof->type();
    if (!ty.IsNoneTy()) {
      if (!IsValidVarDeclType(ty)) {
        decl.addError() << "Invalid variable declaration type: " << ty;
      } else {
        decl.var->var_type = ty;
      }
    } else {
      // We couldn't resolve that specific type by now.
      decl.addError() << "Type cannot be resolved: still none";
    }
  }
}

void TypeChecker::visit(BlockExpr &block)
{
  visit(block.stmts);
  visit(block.expr);
}

void TypeChecker::visit(Probe &probe)
{
  top_level_node_ = &probe;
  visit(probe.attach_points);
  visit(probe.block);
}

void TypeChecker::visit(Subprog &subprog)
{
  // Note that we visit the subprogram and process arguments *after*
  // constructing the stack with the variable states. This is because the
  // arguments, etc. may have types defined in terms of the arguments
  // themselves. We already handle detecting circular dependencies.
  top_level_node_ = &subprog;

  // Validate that arguments are set.
  visit(subprog.args);
  for (SubprogArg *arg : subprog.args) {
    if (arg->typeof->type().IsNoneTy()) {
      arg->addError() << "Unable to resolve argument type.";
    }
  }

  // Visit all statements.
  visit(subprog.block);

  // Validate that the return type is valid.
  visit(subprog.return_type);
  if (subprog.return_type->type().IsNoneTy()) {
    subprog.return_type->addError()
        << "Unable to resolve suitable return type.";
  }
}

bool TypeChecker::check_arg(Call &call, size_t index, const arg_type_spec &spec)
{
  if (spec.skip_check) {
    return true;
  }
  return check_arg(call, spec.type, index, spec.literal);
}

bool TypeChecker::check_call(Call &call)
{
  auto spec = CALL_SPEC.find(call.func);
  if (spec == CALL_SPEC.end()) {
    return true;
  }

  auto ret = true;
  if (spec->second.min_args != spec->second.max_args) {
    ret = check_varargs(call, spec->second.min_args, spec->second.max_args);
  } else {
    ret = check_nargs(call, spec->second.min_args);
  }

  if (!ret) {
    return ret;
  }

  for (size_t i = 0; i < spec->second.arg_types.size() && i < call.vargs.size();
       ++i) {
    ret = check_arg(call, i, spec->second.arg_types.at(i));
  }

  return ret;
}

// Checks the number of arguments passed to a function is correct.
bool TypeChecker::check_nargs(const Call &call, size_t expected_nargs)
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

// Checks the number of arguments passed to a function is within a specified
// range.
bool TypeChecker::check_varargs(const Call &call,
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

// Checks an argument passed to a function is of the correct type.
//
// This function does not check that the function has the correct number of
// arguments. Either check_nargs() or check_varargs() should be called first
// to validate this.
bool TypeChecker::check_arg(Call &call,
                            Type type,
                            size_t index,
                            bool want_literal)
{
  const auto &arg = call.vargs.at(index);

  if (want_literal && (!arg.is_literal() || arg.type().GetTy() != type)) {
    call.addError() << call.func << "() expects a " << type << " literal ("
                    << arg.type().GetTy() << " provided)";
    if (type == Type::string) {
      // If the call requires a string literal and a positional parameter is
      // given, tell user to use str()
      auto *pos_param = arg.as<PositionalParameter>();
      if (pos_param)
        pos_param->addError() << "Use str($" << pos_param->n << ") to treat $"
                              << pos_param->n << " as a string";
    }
    return false;
  } else if (arg.type().GetTy() != type) {
    call.addError() << call.func << "() only supports " << type
                    << " arguments (" << arg.type().GetTy() << " provided)";
    return false;
  }
  return true;
}

Pass CreateTypeCheckerPass()
{
  auto fn = [](ASTContext &ast,
               BPFtrace &b,
               CDefinitions &c_definitions,
               TypeMetadata &types) {
    TypeChecker checker(
        ast, b, c_definitions, types, !b.cmd_.empty() || b.child_ != nullptr);
    checker.visit(ast.root);
  };

  return Pass::create("TypeChecker", fn);
};

} // namespace bpftrace::ast
