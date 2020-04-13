#include "semantic_analyser.h"
#include "arch/arch.h"
#include "ast.h"
#include "fake_map.h"
#include "list.h"
#include "parser.tab.hh"
#include "printf.h"
#include "tracepoint_format_parser.h"
#include "utils.h"
#include <algorithm>
#include <cstring>
#include <regex>
#include <string>
#include <sys/stat.h>

#include <bcc/libbpf.h>

namespace bpftrace {
namespace ast {

static const std::map<std::string, std::tuple<size_t, bool>>& getIntcasts() {
  static const std::map<std::string, std::tuple<size_t, bool>> intcasts = {
    {"uint8", std::tuple<size_t, bool>{1, false}},
    {"int8", std::tuple<size_t, bool>{1, true}},
    {"uint16", std::tuple<size_t, bool>{2, false}},
    {"int16", std::tuple<size_t, bool>{2, true}},
    {"uint32", std::tuple<size_t, bool>{4, false}},
    {"int32", std::tuple<size_t, bool>{4, true}},
    {"uint64", std::tuple<size_t, bool>{8, false}},
    {"int64", std::tuple<size_t, bool>{8, true}},
  };
  return intcasts;
}

// TODO: (fbs) We should get rid of this macro at some point
#define ERR(x, loc)                                                            \
  {                                                                            \
    std::stringstream errbuf;                                                  \
    errbuf << x;                                                               \
    error(errbuf.str(), loc);                                                  \
  }

void SemanticAnalyser::error(const std::string &msg, const location &loc)
{
  bpftrace_.error(err_, loc, msg);
}

void SemanticAnalyser::warning(const std::string &msg, const location &loc)
{
  bpftrace_.warning(out_, loc, msg);
}

void SemanticAnalyser::visit(Integer &integer)
{
  integer.type = SizedType(Type::integer, 8, true);
}

void SemanticAnalyser::visit(PositionalParameter &param)
{
  param.type = SizedType(Type::integer, 8, true);
  switch (param.ptype)
  {
    case PositionalParameterType::positional:
      if (param.n <= 0)
        ERR("$" << std::to_string(param.n) + " is not a valid parameter",
            param.loc);
      if (is_final_pass()) {
        std::string pstr = bpftrace_.get_param(param.n, param.is_in_str);
        if (!is_numeric(pstr) && !param.is_in_str)
        {
          ERR("$" << param.n << " used numerically but given \"" << pstr
                  << "\". Try using str($" << param.n << ").",
              param.loc);
        }
        if (is_numeric(pstr) && param.is_in_str)
        {
          // This is blocked due to current limitations in our codegen
          ERR("$" << param.n << " used in str(), but given numeric value: "
                  << pstr << ". Try $" << param.n << " instead of str($"
                  << param.n << ").",
              param.loc);
        }
      }
      break;
    case PositionalParameterType::count:
      if (is_final_pass() && param.is_in_str) {
        error("use $#, not str($#)", param.loc);
      }
      break;
    default:
      error("unknown parameter type", param.loc);
      param.type = SizedType(Type::none, 0);
      break;
  }
}

void SemanticAnalyser::visit(String &string)
{
  if (!is_compile_time_func(func_) && string.str.size() > STRING_SIZE - 1)
  {
    ERR("String is too long (over " << STRING_SIZE << " bytes): " << string.str,
        string.loc);
  }
  string.type = SizedType(Type::string, STRING_SIZE);
}

void SemanticAnalyser::visit(StackMode &mode)
{
  mode.type = SizedType(Type::stack_mode, 0);
  if (mode.mode == "bpftrace") {
    mode.type.stack_type.mode = bpftrace::StackMode::bpftrace;
  } else if (mode.mode == "perf") {
    mode.type.stack_type.mode = bpftrace::StackMode::perf;
  } else {
    mode.type = SizedType(Type::none, 0);
    error("Unknown stack mode: '" + mode.mode + "'", mode.loc);
  }
}

void SemanticAnalyser::visit(Identifier &identifier)
{
  if (bpftrace_.enums_.count(identifier.ident) != 0) {
    identifier.type = SizedType(Type::integer, 8);
  }
  else {
    identifier.type = SizedType(Type::none, 0);
    error("Unknown identifier: '" + identifier.ident + "'", identifier.loc);
  }
}

void SemanticAnalyser::builtin_args_tracepoint(AttachPoint *attach_point,
                                               Builtin &builtin)
{
  /*
   * tracepoint wildcard expansion, part 2 of 3. This:
   * 1. expands the wildcard, then sets args to be the first matched probe.
   *    This is so that enough of the type information is available to
   *    survive the later semantic analyser checks.
   * 2. sets is_tparg so that codegen does the real type setting after
   *    expansion.
   */
  auto symbol_stream = bpftrace_.get_symbols_from_file(
      "/sys/kernel/debug/tracing/available_events");
  auto matches = bpftrace_.find_wildcard_matches(attach_point->target,
                                                 attach_point->func,
                                                 *symbol_stream);
  if (!matches.empty())
  {
    auto &match = *matches.begin();
    std::string tracepoint_struct = TracepointFormatParser::get_struct_name(
        attach_point->target, match);
    Struct &cstruct = bpftrace_.structs_[tracepoint_struct];
    builtin.type = SizedType(Type::ctx, cstruct.size, tracepoint_struct);
    builtin.type.is_pointer = true;
    builtin.type.is_tparg = true;
  }
}

ProbeType SemanticAnalyser::single_provider_type(void)
{
  ProbeType type = ProbeType::invalid;

  for (auto &attach_point : *probe_->attach_points)
  {
    ProbeType ap = probetype(attach_point->provider);

    if (type == ProbeType::invalid)
      type = ap;

    if (type != ap)
      return ProbeType::invalid;
  }

  return type;
}

void SemanticAnalyser::visit(Builtin &builtin)
{
  if (builtin.ident == "ctx")
  {
    builtin.type = SizedType(Type::ctx, sizeof(uintptr_t), false);
    builtin.type.is_pointer = true;

    ProbeType pt = probetype((*probe_->attach_points)[0]->provider);
    bpf_prog_type bt = progtype(pt);
    for (auto &attach_point : *probe_->attach_points)
    {
      ProbeType pt = probetype(attach_point->provider);
      bpf_prog_type bt2 = progtype(pt);
      if (bt != bt2)
        ERR("ctx cannot be used in different BPF program types: "
                << progtypeName(bt) << " and " << progtypeName(bt2),
            builtin.loc);
    }
    switch (bt)
    {
      case BPF_PROG_TYPE_KPROBE:
        builtin.type.cast_type = "struct pt_regs";
        break;
      case BPF_PROG_TYPE_TRACEPOINT:
        error("Use args instead of ctx in tracepoint", builtin.loc);
        break;
      case BPF_PROG_TYPE_PERF_EVENT:
        builtin.type.cast_type = "struct bpf_perf_event_data";
        break;
      default:
        error("invalid program type", builtin.loc);
        break;
    }
  }
  else if (builtin.ident == "nsecs" || builtin.ident == "elapsed" ||
           builtin.ident == "pid" || builtin.ident == "tid" ||
           builtin.ident == "cgroup" || builtin.ident == "uid" ||
           builtin.ident == "gid" || builtin.ident == "cpu" ||
           builtin.ident == "curtask" || builtin.ident == "rand")
  {
    builtin.type = SizedType(Type::integer, 8, false);
    if (builtin.ident == "cgroup" &&
        !feature_.has_helper_get_current_cgroup_id())
    {
      error("BPF_FUNC_get_current_cgroup_id is not available for your kernel "
            "version",
            builtin.loc);
    }
    else if (builtin.ident == "elapsed")
    {
      needs_elapsed_map_ = true;
    }
    else if (builtin.ident == "curtask")
    {
      /*
      * Retype curtask to its original type: struct task_truct.
      */
      builtin.type.type = Type::cast;
      builtin.type.cast_type = "struct task_struct";
      builtin.type.is_pointer = true;
    }
  }
  else if (builtin.ident == "retval")
  {
    ProbeType type = single_provider_type();

    if (type == ProbeType::kretprobe || type == ProbeType::uretprobe)
    {
      builtin.type = SizedType(Type::integer, 8);
    }
    else if (type == ProbeType::kfunc || type == ProbeType::kretfunc)
    {
      auto it = ap_args_.find("$retval");

      if (it != ap_args_.end())
        builtin.type = it->second;
      else
        ERR("Can't find a field $retval", builtin.loc);
    }
    else
    {
      ERR("The retval builtin can only be used with 'kretprobe' and "
              << "'uretprobe' and 'kfunc' probes"
              << (type == ProbeType::tracepoint
                      ? " (try to use args->ret instead)"
                      : ""),
          builtin.loc);
    }
  }
  else if (builtin.ident == "kstack") {
    builtin.type = SizedType(Type::kstack, StackType());
    needs_stackid_maps_.insert(builtin.type.stack_type);
  }
  else if (builtin.ident == "ustack") {
    builtin.type = SizedType(Type::ustack, StackType());
    needs_stackid_maps_.insert(builtin.type.stack_type);
  }
  else if (builtin.ident == "comm") {
    builtin.type = SizedType(Type::string, COMM_SIZE);
  }
  else if (builtin.ident == "func") {
    for (auto &attach_point : *probe_->attach_points)
    {
      ProbeType type = probetype(attach_point->provider);
      if (type == ProbeType::kprobe ||
          type == ProbeType::kretprobe)
        builtin.type = SizedType(Type::ksym, 8);
      else if (type == ProbeType::uprobe || type == ProbeType::uretprobe)
        builtin.type = SizedType(Type::usym, 16);
      else
        ERR("The func builtin can not be used with '" << attach_point->provider
                                                      << "' probes",
            builtin.loc);
    }
  }
  else if (!builtin.ident.compare(0, 3, "arg") && builtin.ident.size() == 4 &&
      builtin.ident.at(3) >= '0' && builtin.ident.at(3) <= '9') {
    for (auto &attach_point : *probe_->attach_points)
    {
      ProbeType type = probetype(attach_point->provider);
      if (type != ProbeType::kprobe &&
          type != ProbeType::uprobe &&
          type != ProbeType::usdt)
        ERR("The " << builtin.ident << " builtin can only be used with "
                   << "'kprobes', 'uprobes' and 'usdt' probes",
            builtin.loc);
    }
    int arg_num = atoi(builtin.ident.substr(3).c_str());
    if (arg_num > arch::max_arg())
      error(arch::name() + " doesn't support " + builtin.ident, builtin.loc);
    builtin.type = SizedType(Type::integer, 8);
  }
  else if (!builtin.ident.compare(0, 4, "sarg") && builtin.ident.size() == 5 &&
      builtin.ident.at(4) >= '0' && builtin.ident.at(4) <= '9') {
    for (auto &attach_point : *probe_->attach_points)
    {
      ProbeType type = probetype(attach_point->provider);
      if (type != ProbeType::kprobe && type != ProbeType::uprobe)
        error("The " + builtin.ident + " builtin can only be used with " +
                  "'kprobes' and 'uprobes' probes",
              builtin.loc);
      if (is_final_pass() &&
          (attach_point->address != 0 || attach_point->func_offset != 0)) {
        // If sargX values are needed when using an offset, they can be stored in a map
        // when entering the function and then referenced from an offset-based probe
        std::string msg = "Using an address offset with the sargX built-in can"
                          "lead to unexpected behavior ";
        bpftrace_.warning(out_, builtin.loc, msg);
      }
    }
    builtin.type = SizedType(Type::integer, 8);
  }
  else if (builtin.ident == "probe") {
    builtin.type = SizedType(Type::probe, 8);
    probe_->need_expansion = true;
  }
  else if (builtin.ident == "username") {
    builtin.type = SizedType(Type::username, 8);
  }
  else if (builtin.ident == "cpid") {
    if (! bpftrace_.has_child_cmd()) {
      error("cpid cannot be used without child command", builtin.loc);
    }
    builtin.type = SizedType(Type::integer, 4);
  }
  else if (builtin.ident == "args") {
    for (auto &attach_point : *probe_->attach_points)
    {
      ProbeType type = probetype(attach_point->provider);

      if (type == ProbeType::tracepoint)
      {
        probe_->need_expansion = true;
        builtin_args_tracepoint(attach_point, builtin);
      }
    }

    ProbeType type = single_provider_type();

    if (type == ProbeType::tracepoint)
    {
      // no special action in here
    }
    else if (type == ProbeType::kfunc || type == ProbeType::kretfunc)
    {
      builtin.type = SizedType(Type::ctx, 0);
      builtin.type.is_kfarg = true;
    }
    else
    {
      error("The args builtin can only be used with tracepoint/kfunc probes (" +
                probetypeName(type) + " used here)",
            builtin.loc);
    }
  }
  else {
    builtin.type = SizedType(Type::none, 0);
    error("Unknown builtin variable: '" + builtin.ident + "'", builtin.loc);
  }
}

void SemanticAnalyser::visit(Call &call)
{
  // Check for unsafe-ness first. It is likely the most pertinent issue
  // (and should be at the top) for any function call.
  if (bpftrace_.safe_mode_ && is_unsafe_func(call.func)) {
    error(call.func + "() is an unsafe function being used in safe mode",
          call.loc);
  }

  struct func_setter
  {
    func_setter(SemanticAnalyser &analyser, const std::string &s)
        : analyser_(analyser), old_func_(analyser_.func_)
    {
      analyser_.func_ = s;
    }

    ~func_setter()
    {
      analyser_.func_ = old_func_;
    }

  private:
    SemanticAnalyser &analyser_;
    std::string old_func_;
  };

  func_setter scope_bound_func_setter{ *this, call.func };

  if (call.vargs) {
    for (Expression *expr : *call.vargs) {
      expr->accept(*this);
    }
  }

  if (call.func == "hist") {
    check_assignment(call, true, false, false);
    check_nargs(call, 1);
    check_arg(call, Type::integer, 0);

    call.type = SizedType(Type::hist, 8);
  }
  else if (call.func == "lhist") {
    check_assignment(call, true, false, false);
    if (check_nargs(call, 4)) {
      check_arg(call, Type::integer, 0, false);
      check_arg(call, Type::integer, 1, true);
      check_arg(call, Type::integer, 2, true);
      check_arg(call, Type::integer, 3, true);
    }

    if (is_final_pass()) {
      Expression &min_arg = *call.vargs->at(1);
      Expression &max_arg = *call.vargs->at(2);
      Expression &step_arg = *call.vargs->at(3);
      Integer &min = static_cast<Integer&>(min_arg);
      Integer &max = static_cast<Integer&>(max_arg);
      Integer &step = static_cast<Integer&>(step_arg);
      if (step.n <= 0)
      {
        ERR("lhist() step must be >= 1 (" << step.n << " provided)", call.loc);
      }
      else
      {
        int buckets = (max.n - min.n) / step.n;
        if (buckets > 1000)
        {
          ERR("lhist() too many buckets, must be <= 1000 (would need "
                  << buckets << ")",
              call.loc);
        }
      }
      if (min.n < 0)
      {
        ERR("lhist() min must be non-negative (provided min " << min.n << ")",
            call.loc);
      }
      if (min.n > max.n)
      {
        ERR("lhist() min must be less than max (provided min " << min.n
                                                               << " and max ",
            call.loc);
      }
      if ((max.n - min.n) < step.n)
      {
        ERR("lhist() step is too large for the given range (provided step "
                << step.n << " for range " << (max.n - min.n) << ")",
            call.loc);
      }

      // store args for later passing to bpftrace::Map
      auto search = map_args_.find(call.map->ident);
      if (search == map_args_.end())
        map_args_.insert({call.map->ident, *call.vargs});
    }
    call.type = SizedType(Type::lhist, 8);
  }
  else if (call.func == "count") {
    check_assignment(call, true, false, false);
    check_nargs(call, 0);

    call.type = SizedType(Type::count, 8);
  }
  else if (call.func == "sum") {
    bool sign = false;
    check_assignment(call, true, false, false);
    if (check_nargs(call, 1)) {
      sign = call.vargs->at(0)->type.is_signed;
    }
    call.type = SizedType(Type::sum, 8, sign);
  }
  else if (call.func == "min") {
    bool sign = false;
    check_assignment(call, true, false, false);
    if (check_nargs(call, 1)) {
      sign = call.vargs->at(0)->type.is_signed;
    }
    call.type = SizedType(Type::min, 8, sign);
  }
  else if (call.func == "max") {
    bool sign = false;
    check_assignment(call, true, false, false);
    if (check_nargs(call, 1)) {
      sign = call.vargs->at(0)->type.is_signed;
    }
    call.type = SizedType(Type::max, 8, sign);
  }
  else if (call.func == "avg") {
    check_assignment(call, true, false, false);
    check_nargs(call, 1);
    call.type = SizedType(Type::avg, 8, true);
  }
  else if (call.func == "stats") {
    check_assignment(call, true, false, false);
    check_nargs(call, 1);
    call.type = SizedType(Type::stats, 8, true);
  }
  else if (call.func == "delete") {
    check_assignment(call, false, false, false);
    if (check_nargs(call, 1)) {
      auto &arg = *call.vargs->at(0);
      if (!arg.is_map)
        error("delete() expects a map to be provided", call.loc);
    }

    call.type = SizedType(Type::none, 0);
  }
  else if (call.func == "str") {
    if (check_varargs(call, 1, 2)) {
      check_arg(call, Type::integer, 0);
      call.type = SizedType(Type::string, bpftrace_.strlen_);
      if (is_final_pass() && call.vargs->size() > 1) {
        check_arg(call, Type::integer, 1, false);
      }
      if (auto *param = dynamic_cast<PositionalParameter*>(call.vargs->at(0))) {
        param->is_in_str = true;
      }
    }
  }
  else if (call.func == "buf")
  {
    if (!check_varargs(call, 1, 2))
      return;

    auto &arg = *call.vargs->at(0);
    if (!(arg.type.type == Type::integer || arg.type.type == Type::string ||
          arg.type.type == Type::array))
      error(call.func +
                "() expects an integer, string, or array argument but saw " +
                typestr(arg.type.type),
            call.loc);

    size_t max_buffer_size = bpftrace_.strlen_;
    size_t buffer_size = max_buffer_size;

    if (call.vargs->size() == 1)
      if (arg.type.type == Type::array)
        buffer_size = arg.type.pointee_size * arg.type.size;
      else
        error(call.func + "() expects a length argument for non-array type " +
                  typestr(arg.type.type),
              call.loc);
    else
    {
      if (is_final_pass())
        check_arg(call, Type::integer, 1, false);

      auto &size_arg = *call.vargs->at(1);
      if (size_arg.is_literal)
        buffer_size = static_cast<Integer &>(size_arg).n;
    }

    if (buffer_size > max_buffer_size)
    {
      if (is_final_pass())
        warning(call.func + "() length is too long and will be shortened to " +
                    std::to_string(bpftrace_.strlen_) +
                    " bytes (see BPFTRACE_STRLEN)",
                call.loc);

      buffer_size = max_buffer_size;
    }

    buffer_size++; // extra byte is used to embed the length of the buffer
    call.type = SizedType(Type::buffer, buffer_size);

    if (auto *param = dynamic_cast<PositionalParameter *>(call.vargs->at(0)))
    {
      param->is_in_str = true;
    }
  }
  else if (call.func == "ksym" || call.func == "usym") {
    if (check_nargs(call, 1)) {
      // allow symbol lookups on casts (eg, function pointers)
      auto &arg = *call.vargs->at(0);
      if (arg.type.type != Type::integer && arg.type.type != Type::cast)
        error(call.func + "() expects an integer or pointer argument",
              call.loc);
    }

    if (call.func == "ksym")
      call.type = SizedType(Type::ksym, 8);
    else if (call.func == "usym")
      call.type = SizedType(Type::usym, 16);
  }
  else if (call.func == "ntop") {
    if (!check_varargs(call, 1, 2))
      return;

    auto arg = call.vargs->at(0);
    if (call.vargs->size() == 2) {
      arg = call.vargs->at(1);
      check_arg(call, Type::integer, 0);
    }

    if (arg->type.type != Type::integer && arg->type.type != Type::array)
      ERR(call.func << "() expects an integer or array argument, got "
                    << arg->type.type,
          call.loc);

    // Kind of:
    //
    // struct {
    //   int af_type;
    //   union {
    //     char[4] inet4;
    //     char[16] inet6;
    //   }
    // }
    int buffer_size = 24;
    if (arg->type.type == Type::array) {
      if (arg->type.elem_type != Type::integer || arg->type.pointee_size != 1 || !(arg->type.size == 4 || arg->type.size == 16)) {
        error(call.func + "() invalid array", call.loc);
      }
    }
    call.type = SizedType(Type::inet, buffer_size);
    call.type.is_internal = true;
  }
  else if (call.func == "join") {
    check_assignment(call, false, false, false);
    check_varargs(call, 1, 2);
    check_arg(call, Type::integer, 0);
    call.type = SizedType(Type::none, 0);
    needs_join_map_ = true;

    if (is_final_pass()) {
      if (call.vargs && call.vargs->size() > 1) {
        if (check_arg(call, Type::string, 1, true)) {
          auto &join_delim_arg = *call.vargs->at(1);
          String &join_delim_str = static_cast<String&>(join_delim_arg);
          bpftrace_.join_args_.push_back(join_delim_str.str);
        }
      } else {
        std::string join_delim_default = " ";
        bpftrace_.join_args_.push_back(join_delim_default);
      }
    }
  }
  else if (call.func == "reg") {
    if (check_nargs(call, 1)) {
      for (auto &attach_point : *probe_->attach_points) {
        ProbeType type = probetype(attach_point->provider);
        if (type == ProbeType::tracepoint) {
          error("The reg function cannot be used with 'tracepoint' probes",
                call.loc);
          continue;
        }
      }

      if (check_arg(call, Type::string, 0, true)) {
        auto &arg = *call.vargs->at(0);
        auto &reg_name = static_cast<String&>(arg).str;
        int offset = arch::offset(reg_name);;
        if (offset == -1) {
          ERR("'" << reg_name
                  << "' is not a valid register on this architecture"
                  << " (" << arch::name() << ")",
              call.loc);
        }
      }
    }

    call.type = SizedType(Type::integer, 8);
  }
  else if (call.func == "kaddr") {
    if (check_nargs(call, 1)) {
      check_arg(call, Type::string, 0, true);
    }
    call.type = SizedType(Type::integer, 8);
  }
  else if (call.func == "uaddr")
  {
    if (!check_nargs(call, 1))
      return;
    if (!(check_arg(call, Type::string, 0, true) && check_symbol(call, 0)))
      return;

    std::vector<int> sizes;
    auto &name = static_cast<String &>(*call.vargs->at(0)).str;
    for (auto &ap : *probe_->attach_points)
    {
      ProbeType type = probetype(ap->provider);
      if (type != ProbeType::usdt && type != ProbeType::uretprobe &&
          type != ProbeType::uprobe)
      {
        bpftrace_.error(
            err_,
            call.loc,
            "uaddr can only be used with u(ret)probes and usdt probes");
        sizes.push_back(0);
        continue;
      }
      struct symbol sym = {};
      int err = bpftrace_.resolve_uname(name, &sym, ap->target);
      if (err < 0 || sym.address == 0)
      {
        bpftrace_.error(err_,
                        call.loc,
                        "Could not resolve symbol: " + ap->target + ":" + name);
      }
      sizes.push_back(sym.size);
    }

    for (size_t i = 1; i < sizes.size(); i++)
    {
      if (sizes.at(0) != sizes.at(i))
      {
        std::stringstream msg;
        msg << "Symbol size mismatch between probes. Symbol \"" << name
            << "\" has size " << sizes.at(0) << " for probe \""
            << probe_->attach_points->at(0)->name("") << "\" but size "
            << sizes.at(i) << " for probe \""
            << probe_->attach_points->at(i)->name("") << "\"";
        bpftrace_.error(err_, call.loc, msg.str());
      }
    }
    call.type = SizedType(Type::integer, 8);
    call.type.is_pointer = true;
    switch (sizes.at(0))
    {
      case 1:
      case 2:
      case 4:
        call.type.pointee_size = sizes.at(0);
        break;
      default:
        call.type.pointee_size = 8;
    }
  }
  else if (call.func == "cgroupid") {
    if (check_nargs(call, 1)) {
      check_arg(call, Type::string, 0, true);
    }
    call.type = SizedType(Type::integer, 8);
  }
  else if (call.func == "printf" || call.func == "system" || call.func == "cat")
  {
    check_assignment(call, false, false, false);
    if (check_varargs(call, 1, 7))
    {
      check_arg(call, Type::string, 0, true);
      if (is_final_pass())
      {
        auto &fmt_arg = *call.vargs->at(0);
        String &fmt = static_cast<String&>(fmt_arg);
        std::vector<Field> args;
        for (auto iter = call.vargs->begin() + 1; iter != call.vargs->end();
             iter++)
        {
          auto ty = (*iter)->type;
          // Promote to 64-bit if it's not an array type
          if (!ty.IsArray())
            ty.size = 8;
          args.push_back(Field{
            .type =  ty,
            .offset = 0,
            .is_bitfield = false,
            .bitfield = Bitfield{
              .read_bytes = 0,
              .access_rshift = 0,
              .mask = 0,
            },
          });
        }
        std::string msg = verify_format_string(fmt.str, args);
        if (msg != "")
        {
          error(msg, call.loc);
        }

        if (call.func == "printf")
          bpftrace_.printf_args_.emplace_back(fmt.str, args);
        else if (call.func == "system")
          bpftrace_.system_args_.emplace_back(fmt.str, args);
        else
          bpftrace_.cat_args_.emplace_back(fmt.str, args);
      }
    }

    call.type = SizedType(Type::none, 0);
  }
  else if (call.func == "exit") {
    check_nargs(call, 0);
  }
  else if (call.func == "print") {
    check_assignment(call, false, false, false);
    if (check_varargs(call, 1, 3)) {
      auto &arg = *call.vargs->at(0);
      if (!arg.is_map)
        error("print() expects a map to be provided", call.loc);
      else {
        Map &map = static_cast<Map&>(arg);
        map.skip_key_validation = true;
        if (map.vargs != nullptr) {
          ERR("The map passed to " << call.func << "() should not be "
                                   << "indexed by a key",
              call.loc);
        }
      }
      if (is_final_pass()) {
        if (call.vargs->size() > 1)
          check_arg(call, Type::integer, 1, true);
        if (call.vargs->size() > 2)
          check_arg(call, Type::integer, 2, true);
      }
    }
  }
  else if (call.func == "clear") {
    check_assignment(call, false, false, false);
    if (check_nargs(call, 1)) {
      auto &arg = *call.vargs->at(0);
      if (!arg.is_map)
        error("clear() expects a map to be provided", call.loc);
      else {
        Map &map = static_cast<Map&>(arg);
        map.skip_key_validation = true;
        if (map.vargs != nullptr) {
          ERR("The map passed to " << call.func << "() should not be "
                                   << "indexed by a key",
              call.loc);
        }
      }
    }
  }
  else if (call.func == "zero") {
    check_assignment(call, false, false, false);
    if (check_nargs(call, 1)) {
      auto &arg = *call.vargs->at(0);
      if (!arg.is_map)
        error("zero() expects a map to be provided", call.loc);
      else {
        Map &map = static_cast<Map&>(arg);
        map.skip_key_validation = true;
        if (map.vargs != nullptr) {
          ERR("The map passed to " << call.func << "() should not be "
                                   << "indexed by a key",
              call.loc);
        }
      }
    }
  }
  else if (call.func == "time") {
    check_assignment(call, false, false, false);
    if (check_varargs(call, 0, 1)) {
      if (is_final_pass()) {
        if (call.vargs && call.vargs->size() > 0) {
          if (check_arg(call, Type::string, 0, true)) {
            auto &fmt_arg = *call.vargs->at(0);
            String &fmt = static_cast<String&>(fmt_arg);
            bpftrace_.time_args_.push_back(fmt.str);
          }
        } else {
          std::string fmt_default = "%H:%M:%S\n";
          bpftrace_.time_args_.push_back(fmt_default.c_str());
        }
      }
    }
  }
  else if (call.func == "kstack") {
    check_stack_call(call, Type::kstack);
  }
  else if (call.func == "ustack") {
    check_stack_call(call, Type::ustack);
  }
  else if (call.func == "signal") {
    if (!feature_.has_helper_send_signal())
    {
      error("BPF_FUNC_send_signal not available for your kernel version",
            call.loc);
    }

    check_assignment(call, false, false, false);

    if (!check_varargs(call, 1, 1)) {
      return;
    }

    auto &arg = *call.vargs->at(0);
    if (arg.type.type == Type::string && arg.is_literal) {
      auto sig = static_cast<String&>(arg).str;
      if (signal_name_to_num(sig) < 1) {
        error(sig + " is not a valid signal", call.loc);
      }
    }
    else if(arg.type.type == Type::integer && arg.is_literal) {
      auto sig = static_cast<Integer&>(arg).n;
      if (sig < 1 || sig > 64) {
        error(std::to_string(sig) +
                  " is not a valid signal, allowed range: [1,64]",
              call.loc);
      }
    }
    else if(arg.type.type != Type::integer) {
      error("signal only accepts string literals or integers", call.loc);
    }

    for (auto &ap : *probe_->attach_points) {
      ProbeType type = probetype(ap->provider);
      if (ap->provider == "BEGIN" || ap->provider == "END") {
        error(call.func + " can not be used with \"" + ap->provider +
                  "\" probes",
              call.loc);
      }
      else if (type == ProbeType::interval
          || type == ProbeType::software
          || type == ProbeType::hardware
          || type == ProbeType::watchpoint) {
        error(call.func + " can not be used with \"" + ap->provider +
                  "\" probes",
              call.loc);
      }
    }
  }
  else if (call.func == "strncmp") {
    if (check_nargs(call, 3)) {
      check_arg(call, Type::string, 0);
      check_arg(call, Type::string, 1);
      if (check_arg(call, Type::integer, 2, true)){
        Integer &size = static_cast<Integer&>(*call.vargs->at(2));
        if (size.n < 0)
          error("Builtin strncmp requires a non-negative size", call.loc);
      }
    }
    call.type = SizedType(Type::integer, 8);
  }
  else if (call.func == "override")
  {
    if (!feature_.has_helper_override_return())
    {
      error("BPF_FUNC_override_return not available for your kernel version",
            call.loc);
    }

    check_assignment(call, false, false, false);
    if (check_varargs(call, 1, 1))
    {
      check_arg(call, Type::integer, 0, false);
    }
    for (auto &attach_point : *probe_->attach_points)
    {
      ProbeType type = probetype(attach_point->provider);
      if (type != ProbeType::kprobe)
      {
        error(call.func + " can only be used with kprobes.", call.loc);
      }
    }
  }
  else {
    error("Unknown function: '" + call.func + "'", call.loc);
    call.type = SizedType(Type::none, 0);
  }
}

void SemanticAnalyser::check_stack_call(Call &call, Type type) {
  call.type = SizedType(type, StackType());
  if (check_varargs(call, 0, 2) && is_final_pass()) {
    StackType stack_type;
    if (call.vargs) {
      switch (call.vargs->size()) {
        case 0: break;
        case 1: {
          auto &arg = *call.vargs->at(0);
          // If we have a single argument it can be either
          // stack-mode or stack-size
          if (arg.type.type == Type::stack_mode) {
            if (check_arg(call, Type::stack_mode, 0, true))
              stack_type.mode = static_cast<StackMode&>(arg).type.stack_type.mode;
          } else {
            if (check_arg(call, Type::integer, 0, true))
              stack_type.limit = static_cast<Integer&>(arg).n;
          }
          break;
        }
        case 2: {
          if (check_arg(call, Type::stack_mode, 0, true)) {
            auto &mode_arg = *call.vargs->at(0);
            stack_type.mode = static_cast<StackMode&>(mode_arg).type.stack_type.mode;
          }

          if (check_arg(call, Type::integer, 1, true)) {
            auto &limit_arg = *call.vargs->at(1);
            stack_type.limit = static_cast<Integer&>(limit_arg).n;
          }
          break;
        }
        default:
          error("Invalid number of arguments", call.loc);
          break;
      }
    }
    if (stack_type.limit > MAX_STACK_SIZE)
    {
      ERR(call.func << "([int limit]): limit shouldn't exceed "
                    << MAX_STACK_SIZE << ", " << stack_type.limit << " given",
          call.loc);
    }
    call.type = SizedType(type, stack_type);
    needs_stackid_maps_.insert(stack_type);
  }
}

void SemanticAnalyser::visit(Map &map)
{
  MapKey key;

  if (map.vargs) {
    for (unsigned int i = 0; i < map.vargs->size(); i++){
      Expression * expr = map.vargs->at(i);
      expr->accept(*this);

      // Insert a cast to 64 bits if needed by injecting
      // a cast into the ast.
      if (expr->type.type == Type::integer && expr->type.size < 8) {
        std::string type = expr->type.is_signed ? "int64" : "uint64";
        Expression * cast = new ast::Cast(type, false, expr);
        cast->accept(*this);
        map.vargs->at(i) = cast;
        expr = cast;
      }
      else if (expr->type.type == Type::ctx)
      {
        // map functions only accepts a pointer to a element in the stack
        error("context cannot be used as a map key", map.loc);
      }

      if (is_final_pass()) {
        // Skip is_signed when comparing keys to not break existing scripts
        // which use maps as a lookup table
        // TODO (fbs): This needs a better solution
        SizedType keytype = expr->type;
        keytype.is_signed = false;
        key.args_.push_back(keytype);
      }
    }
  }

  if (is_final_pass()) {
    if (!map.skip_key_validation) {
      auto search = map_key_.find(map.ident);
      if (search != map_key_.end()) {
        if (search->second != key) {
          ERR("Argument mismatch for " << map.ident << ": "
                                       << "trying to access with arguments: "
                                       << key.argument_type_list()
                                       << " when map expects arguments: "
                                       << search->second.argument_type_list(),
              map.loc);
        }
      }
      else {
        map_key_.insert({map.ident, key});
      }
    }
  }

  auto search_val = map_val_.find(map.ident);
  if (search_val != map_val_.end()) {
    map.type = search_val->second;
  }
  else {
    if (is_final_pass()) {
      error("Undefined map: " + map.ident, map.loc);
    }
    map.type = SizedType(Type::none, 0);
  }
}

void SemanticAnalyser::visit(Variable &var)
{
  auto search_val = variable_val_.find(var.ident);
  if (search_val != variable_val_.end()) {
    var.type = search_val->second;
  }
  else {
    error("Undefined or undeclared variable: " + var.ident, var.loc);
    var.type = SizedType(Type::none, 0);
  }
}

void SemanticAnalyser::visit(ArrayAccess &arr)
{
  arr.expr->accept(*this);
  arr.indexpr->accept(*this);

  SizedType &type = arr.expr->type;
  SizedType &indextype = arr.indexpr->type;

  if (is_final_pass()) {
    if (!((type.type == Type::array || type.type == Type::ctx) &&
          type.elem_type != Type::none))
      error("The array index operator [] can only be used on arrays.", arr.loc);

    if (indextype.type == Type::integer && arr.indexpr->is_literal) {
      Integer *index = static_cast<Integer *>(arr.indexpr);

      if ((size_t) index->n >= type.size)
        ERR("the index " << index->n << " is out of bounds for array of size "
                         << type.size,
            arr.loc);
    }
    else {
      error("The array index operator [] only accepts literal integer indices.",
            arr.loc);
    }
  }

  arr.type = SizedType(type.elem_type, type.pointee_size, type.is_signed);
}

void SemanticAnalyser::visit(Binop &binop)
{
  binop.left->accept(*this);
  binop.right->accept(*this);
  Type &lhs = binop.left->type.type;
  Type &rhs = binop.right->type.type;
  bool lsign = binop.left->type.is_signed;
  bool rsign = binop.right->type.is_signed;

  std::stringstream buf;
  if (is_final_pass()) {
    if ((lhs != rhs) &&
      // allow integer to cast pointer comparisons (eg, ptr != 0):
      !(lhs == Type::cast && rhs == Type::integer) &&
      !(lhs == Type::integer && rhs == Type::cast)) {
      buf << "Type mismatch for '" << opstr(binop) << "': ";
      buf << "comparing '" << lhs << "' ";
      buf << "with '" << rhs << "'";
      bpftrace_.error(err_, binop.left->loc + binop.right->loc, buf.str());
      buf.str({});
    }
    // Follow what C does
    else if (lhs == Type::integer && rhs == Type::integer) {
      auto get_int_literal = [](const auto expr) -> long {
        return static_cast<ast::Integer*>(expr)->n;
      };
      auto left = binop.left;
      auto right = binop.right;

      // First check if operand signedness is the same
      if (lsign != rsign) {
        // Convert operands to unsigned if it helps make (lsign == rsign)
        //
        // For example:
        //
        // unsigned int a;
        // if (a > 10) ...;
        //
        // No warning should be emitted as we know that 10 can be
        // represented as unsigned int
        if (lsign && !rsign && left->is_literal && get_int_literal(left) >= 0) {
          left->type.is_signed = lsign = false;
        }
        // The reverse (10 < a) should also hold
        else if (!lsign && rsign && right->is_literal && get_int_literal(right) >= 0) {
          right->type.is_signed = rsign = false;
        }
        else {
          switch (binop.op) {
          case bpftrace::Parser::token::EQ:
          case bpftrace::Parser::token::NE:
          case bpftrace::Parser::token::LE:
          case bpftrace::Parser::token::GE:
          case bpftrace::Parser::token::LT:
          case bpftrace::Parser::token::GT:
            buf << "comparison of integers of different signs: '"
                << binop.left->type << "' and '"
                << binop.right->type << "'"
                << " can lead to undefined behavior";
            warning(buf.str(), binop.loc);
            buf.str({});
            break;
          case bpftrace::Parser::token::PLUS:
          case bpftrace::Parser::token::MINUS:
          case bpftrace::Parser::token::MUL:
          case bpftrace::Parser::token::DIV:
          case bpftrace::Parser::token::MOD:
            buf << "arithmetic on integers of different signs: '"
                << left->type << "' and '" << right->type << "'"
                << " can lead to undefined behavior";
            warning(buf.str(), binop.loc);
            buf.str({});
            break;
          default:
            break;
          }
        }
      }

      // Next, warn on any operations that require signed division.
      //
      // SDIV is not implemented for bpf. See Documentation/bpf/bpf_design_QA
      // in kernel sources
      if (binop.op == bpftrace::Parser::token::DIV ||
          binop.op == bpftrace::Parser::token::MOD) {
        // Convert operands to unsigned if possible
        if (lsign && left->is_literal && get_int_literal(left) >= 0)
          left->type.is_signed = lsign = false;
        if (rsign && right->is_literal && get_int_literal(right) >= 0)
          right->type.is_signed = rsign = false;

        // If they're still signed, we have to warn
        if (lsign || rsign) {
          buf << "signed operands for '" << opstr(binop)
              << "' can lead to undefined behavior "
              << "(cast to unsigned to silence warning)";
          bpftrace_.warning(out_, binop.loc, buf.str());
          buf.str({});
        }
      }
    }
    else if (!(lhs == Type::integer && rhs == Type::integer)
             && binop.op != Parser::token::EQ
             && binop.op != Parser::token::NE) {
      ERR("The " << opstr(binop)
                 << " operator can not be used on expressions of types " << lhs
                 << ", " << rhs,
          binop.loc);
    }
  }

  bool is_signed = lsign && rsign;
  switch (binop.op) {
    case bpftrace::Parser::token::LEFT:
    case bpftrace::Parser::token::RIGHT:
      is_signed = lsign;
      break;
    default:
      break;
  }

  binop.type = SizedType(Type::integer, 8, is_signed);
}

void SemanticAnalyser::visit(Unop &unop)
{
  if (unop.op == Parser::token::INCREMENT ||
      unop.op == Parser::token::DECREMENT) {
    // Handle ++ and -- before visiting unop.expr, because these
    // operators should be able to work with undefined maps.
    if (!unop.expr->is_map && !unop.expr->is_variable) {
      error("The " + opstr(unop) +
                " operator must be applied to a map or variable",
            unop.loc);
    }
    if (unop.expr->is_map) {
      Map &map = static_cast<Map&>(*unop.expr);
      assign_map_type(map, SizedType(Type::integer, 8, true));
    }
  }

  unop.expr->accept(*this);

  SizedType &type = unop.expr->type;
  if (is_final_pass() && !(type.type == Type::integer) &&
      !((type.type == Type::cast || type.type == Type::ctx) &&
        unop.op == Parser::token::MUL))
  {
    ERR("The " << opstr(unop)
               << " operator can not be used on expressions of type '" << type
               << "'",
        unop.loc);
  }

  if (unop.op == Parser::token::MUL) {
    if (type.type == Type::cast || type.type == Type::ctx)
    {
      if (type.is_pointer) {
        int cast_size;
        auto &intcasts = getIntcasts();
        auto k_v = intcasts.find(type.cast_type);
        if (k_v == intcasts.end() && bpftrace_.structs_.count(type.cast_type) == 0) {
          ERR("Unknown struct/union: '" << type.cast_type << "'", unop.loc);
          return;
        }
        if (k_v != intcasts.end()) {
          auto &v = k_v->second;
          unop.type = SizedType(Type::integer, std::get<0>(v), std::get<1>(v), k_v->first);
        } else {
          cast_size = bpftrace_.structs_[type.cast_type].size;
          unop.type = SizedType(type.type, cast_size, type.cast_type);
        }
        unop.type.is_tparg = type.is_tparg;
      }
      else if (type.is_kfarg)
      {
        // args->arg access, we need to push the args builtin
        // type further through the expression ladder
        unop.type = type;
      }
      else {
        ERR("Can not dereference struct/union of type '"
                << type.cast_type << "'. "
                << "It is not a pointer.",
            unop.loc);
      }
    }
    else if (type.type == Type::integer) {
      unop.type = SizedType(Type::integer, type.size, type.is_signed);
    }
  }
  else if (unop.op == Parser::token::LNOT) {
    unop.type = SizedType(Type::integer, type.size, false);
  }
  else {
    unop.type = SizedType(Type::integer, 8, type.is_signed);
  }
}

void SemanticAnalyser::visit(Ternary &ternary)
{
  ternary.cond->accept(*this);
  ternary.left->accept(*this);
  ternary.right->accept(*this);
  Type &lhs = ternary.left->type.type;
  Type &rhs = ternary.right->type.type;
  if (is_final_pass()) {
    if (lhs != rhs) {
      ERR("Ternary operator must return the same type: "
              << "have '" << lhs << "' "
              << "and '" << rhs << "'",
          ternary.loc);
    }
  }
  if (lhs == Type::string)
    ternary.type = SizedType(lhs, STRING_SIZE);
  else if (lhs == Type::integer)
    ternary.type = SizedType(lhs, 8, ternary.left->type.is_signed);
  else {
    ERR("Ternary return type unsupported " << lhs, ternary.loc);
  }
}

void SemanticAnalyser::visit(If &if_block)
{
  if_block.cond->accept(*this);

  for (Statement *stmt : *if_block.stmts) {
    stmt->accept(*this);
  }

  if (if_block.else_stmts) {
    for (Statement *stmt : *if_block.else_stmts) {
      stmt->accept(*this);
    }
  }
}

void SemanticAnalyser::visit(Unroll &unroll)
{
  if (unroll.var > 20)
  {
    error("unroll maximum value is 20", location(0));
  }
  else if (unroll.var < 1)
  {
    error("unroll minimum value is 1", location(0));
  }

  for (int i=0; i < unroll.var; i++) {
    for (Statement *stmt : *unroll.stmts)
    {
      stmt->accept(*this);
    }
  }
}

void SemanticAnalyser::visit(FieldAccess &acc)
{
  acc.expr->accept(*this);

  SizedType &type = acc.expr->type;
  if (type.type != Type::cast && type.type != Type::ctx)
  {
    if (is_final_pass()) {
      ERR("Can not access field '" << acc.field << "' on expression of type '"
                                   << type << "'",
          acc.loc);
    }
    return;
  }

  if (type.is_kfarg)
  {
    auto it = ap_args_.find(acc.field);

    if (it != ap_args_.end())
      acc.type = it->second;
    else
      error("Can't find a field", acc.loc);
    return;
  }

  if (type.is_pointer) {
    ERR("Can not access field '"
            << acc.field << "' on type '" << type.cast_type
            << "'. Try dereferencing it first, or using '->'",
        acc.loc);
    return;
  }
  if (bpftrace_.structs_.count(type.cast_type) == 0) {
    ERR("Unknown struct/union: '" << type.cast_type << "'", acc.loc);
    return;
  }

  std::map<std::string, FieldsMap> structs;

  if (type.is_tparg) {
    for (AttachPoint *attach_point : *probe_->attach_points) {
      if (probetype(attach_point->provider) != ProbeType::tracepoint)
      {
        // The args builtin can only be used with tracepoint
        // an error message is already generated in visit(Builtin)
        // just continue semantic analysis
        continue;
      }

      auto symbol_stream = bpftrace_.get_symbols_from_file(
          "/sys/kernel/debug/tracing/available_events");
      auto matches = bpftrace_.find_wildcard_matches(attach_point->target,
                                                     attach_point->func,
                                                     *symbol_stream);
      for (auto &match : matches) {
        std::string tracepoint_struct =
            TracepointFormatParser::get_struct_name(attach_point->target,
                                                    match);
        structs[tracepoint_struct] = bpftrace_.structs_[tracepoint_struct].fields;
      }
    }
  } else {
    structs[type.cast_type] = bpftrace_.structs_[type.cast_type].fields;
  }

  for (auto it : structs) {
    std::string cast_type = it.first;
    FieldsMap fields = it.second;
    if (fields.count(acc.field) == 0) {
      ERR("Struct/union of type '" << cast_type << "' does not contain "
                                   << "a field named '" << acc.field << "'",
          acc.loc);
    }
    else {
      acc.type = fields[acc.field].type;
      if (acc.expr->type.type == Type::ctx &&
          ((acc.type.type == Type::cast && !acc.type.is_pointer) ||
           acc.type.type == Type::array))
      {
        // e.g., ((struct bpf_perf_event_data*)ctx)->regs.ax
        // in this case, the type of FieldAccess to "regs" is Type::ctx
        acc.type.type = Type::ctx;
      }
      acc.type.is_internal = type.is_internal;
    }
  }
}

void SemanticAnalyser::visit(Cast &cast)
{
  cast.expr->accept(*this);

  bool is_ctx = cast.expr->type.type == Type::ctx;
  auto &intcasts = getIntcasts();
  auto k_v = intcasts.find(cast.cast_type);
  int cast_size;

  if (k_v == intcasts.end() && bpftrace_.structs_.count(cast.cast_type) == 0) {
    ERR("Unknown struct/union: '" << cast.cast_type << "'", cast.loc);
    return;
  }

  if (cast.is_pointer) {
    if (k_v != intcasts.end() && is_ctx)
      error("Integer pointer casts are not supported for type: ctx", cast.loc);
    cast_size = sizeof(uintptr_t);
    cast.type = SizedType(is_ctx ? Type::ctx : Type::cast,
                          cast_size,
                          cast.cast_type);
    cast.type.is_pointer = cast.is_pointer;
    return;
  }

  if (k_v != intcasts.end()) {
    auto &v = k_v->second;
    cast.type = SizedType(Type::integer, std::get<0>(v), std::get<1>(v), k_v->first);

    auto rhs = cast.expr->type.type;
    // Casting Type::ctx to Type::integer is supported to access a
    // tracepoint's __data_loc field. See #990 and #770
    // In this case, the context information will be lost
    if (!(rhs == Type::integer || rhs == Type::cast || rhs == Type::ctx))
    {
      ERR("Casts are not supported for type: \"" << rhs << "\"", cast.loc);
    }

    return;
  }

  cast_size = bpftrace_.structs_[cast.cast_type].size;
  cast.type = SizedType(is_ctx ? Type::ctx : Type::cast,
                        cast_size,
                        cast.cast_type);
  cast.type.is_pointer = cast.is_pointer;
}

void SemanticAnalyser::visit(ExprStatement &expr)
{
  expr.expr->accept(*this);
}

void SemanticAnalyser::visit(AssignMapStatement &assignment)
{
  assignment.map->accept(*this);
  assignment.expr->accept(*this);

  assign_map_type(*assignment.map, assignment.expr->type);

  const std::string &map_ident = assignment.map->ident;
  auto type = assignment.expr->type.type;
  if (type == Type::cast)
  {
    std::string cast_type = assignment.expr->type.cast_type;
    std::string curr_cast_type = map_val_[map_ident].cast_type;
    if (curr_cast_type != "" && curr_cast_type != cast_type) {
      ERR("Type mismatch for "
              << map_ident << ": "
              << "trying to assign value of type '" << cast_type
              << "' when map already contains a value of type '"
              << curr_cast_type,
          assignment.loc);
    }
    else {
      map_val_[map_ident].cast_type = cast_type;
      map_val_[map_ident].is_internal = true;
    }
  }
  else if (type == Type::string)
  {
    auto map_size = map_val_[map_ident].size;
    auto expr_size = assignment.expr->type.size;
    if (map_size != expr_size)
    {
      std::stringstream buf;
      buf << "String size mismatch: " << map_size << " != " << expr_size << ".";
      if (map_size < expr_size)
      {
        buf << " The value may be truncated.";
        bpftrace_.warning(out_, assignment.loc, buf.str());
      }
      else
      {
        // bpf_map_update_elem() expects map_size-length value
        error(buf.str(), assignment.loc);
      }
    }
  }
  else if (type == Type::buffer)
  {
    auto map_size = map_val_[map_ident].size;
    auto expr_size = assignment.expr->type.size;
    if (map_size != expr_size)
    {
      std::stringstream buf;
      buf << "Buffer size mismatch: " << map_size << " != " << expr_size << ".";
      if (map_size < expr_size)
      {
        buf << " The value may be truncated.";
        bpftrace_.warning(out_, assignment.loc, buf.str());
      }
      else
      {
        // bpf_map_update_elem() expects map_size-length value
        error(buf.str(), assignment.loc);
      }
    }
  }
  else if (type == Type::ctx)
  {
    // bpf_map_update_elem() only accepts a pointer to a element in the stack
    error("context cannot be assigned to a map", assignment.loc);
  }
}

void SemanticAnalyser::visit(AssignVarStatement &assignment)
{
  assignment.expr->accept(*this);

  std::string var_ident = assignment.var->ident;
  auto search = variable_val_.find(var_ident);
  assignment.var->type = assignment.expr->type;
  if (search != variable_val_.end()) {
    if (search->second.type == Type::none) {
      if (is_final_pass()) {
        error("Undefined variable: " + var_ident, assignment.loc);
      }
      else {
        search->second = assignment.expr->type;
      }
    }
    else if (search->second.type != assignment.expr->type.type) {
      ERR("Type mismatch for "
              << var_ident << ": "
              << "trying to assign value of type '" << assignment.expr->type
              << "' when variable already contains a value of type '"
              << search->second,
          assignment.loc);
    }
  }
  else {
    // This variable hasn't been seen before
    variable_val_.insert({var_ident, assignment.expr->type});
    assignment.var->type = assignment.expr->type;
  }

  if (assignment.expr->type.type == Type::cast ||
      assignment.expr->type.type == Type::ctx)
  {
    std::string cast_type = assignment.expr->type.cast_type;
    std::string curr_cast_type = variable_val_[var_ident].cast_type;
    if (curr_cast_type != "" && curr_cast_type != cast_type) {
      ERR("Type mismatch for "
              << var_ident << ": "
              << "trying to assign value of type '" << cast_type
              << "' when variable already contains a value of type '"
              << curr_cast_type,
          assignment.loc);
    }
    else {
      variable_val_[var_ident].cast_type = cast_type;
    }
  }
  else if (assignment.expr->type.type == Type::string)
  {
    auto var_size = variable_val_[var_ident].size;
    auto expr_size = assignment.expr->type.size;
    if (var_size != expr_size)
    {
      std::stringstream buf;
      buf << "String size mismatch: " << var_size << " != " << expr_size << ".";
      if (var_size < expr_size)
        buf << " The value may be truncated.";
      else
        buf << " The value may contain garbage.";
      bpftrace_.warning(out_, assignment.loc, buf.str());
    }
  }
  else if (assignment.expr->type.type == Type::buffer)
  {
    auto var_size = variable_val_[var_ident].size;
    auto expr_size = assignment.expr->type.size;
    if (var_size != expr_size)
    {
      std::stringstream buf;
      buf << "Buffer size mismatch: " << var_size << " != " << expr_size << ".";
      if (var_size < expr_size)
        buf << " The value may be truncated.";
      else
        buf << " The value may contain garbage.";
      bpftrace_.warning(out_, assignment.loc, buf.str());
    }
  }
}

void SemanticAnalyser::visit(Predicate &pred)
{
  pred.expr->accept(*this);
  if (is_final_pass() &&
      ((pred.expr->type.type != Type::integer) &&
       (!(pred.expr->type.is_pointer && (pred.expr->type.type == Type::cast ||
                                         pred.expr->type.type == Type::ctx)))))
  {
    ERR("Invalid type for predicate: " << pred.expr->type.type, pred.loc);
  }
}

void SemanticAnalyser::visit(AttachPoint &ap)
{
  ap.provider = probetypeName(ap.provider);

  if (ap.provider == "kprobe" || ap.provider == "kretprobe") {
    if (ap.target != "")
      error("kprobes should not have a target", ap.loc);
    if (ap.func == "")
      error("kprobes should be attached to a function", ap.loc);
  }
  else if (ap.provider == "uprobe" || ap.provider == "uretprobe") {
    if (ap.target == "")
      error(ap.provider + " should have a target", ap.loc);
    if (ap.func == "" && ap.address == 0)
      error(ap.provider + " should be attached to a function and/or address",
            ap.loc);

    if (ap.provider == "uretprobe" && ap.func_offset != 0)
      error("uretprobes can not be attached to a function offset", ap.loc);

    auto paths = resolve_binary_path(ap.target, bpftrace_.pid_);
    switch (paths.size())
    {
    case 0:
      error("uprobe target file '" + ap.target +
                "' does not exist or is not executable",
            ap.loc);
      break;
    case 1:
      ap.target = paths.front();
      break;
    default:
      // If we are doing a PATH lookup (ie not glob), we follow shell
      // behavior and take the first match.
      if (ap.target.find("*") == std::string::npos)
      {
        warning("attaching to uprobe target file '" + paths.front() +
                    "' but matched " + std::to_string(paths.size()) +
                    " binaries",
                ap.loc);
        ap.target = paths.front();
      }
      else
        error("uprobe target file '" + ap.target +
                  "' must refer to a unique binary but matched " +
                  std::to_string(paths.size()),
              ap.loc);
    }
  }
  else if (ap.provider == "usdt") {
    if (ap.func == "")
      error("usdt probe must have a target function or wildcard", ap.loc);

    if (ap.target != "") {
      auto paths = resolve_binary_path(ap.target, bpftrace_.pid_);
      switch (paths.size())
      {
      case 0:
        error("usdt target file '" + ap.target +
                  "' does not exist or is not executable",
              ap.loc);
        break;
      case 1:
        ap.target = paths.front();
        break;
      default:
        // If we are doing a PATH lookup (ie not glob), we follow shell
        // behavior and take the first match.
        if (ap.target.find("*") == std::string::npos)
        {
          warning("attaching to usdt target file '" + paths.front() +
                      "' but matched " + std::to_string(paths.size()) +
                      " binaries",
                  ap.loc);
          ap.target = paths.front();
        }
        else
          error("usdt target file '" + ap.target +
                    "' must refer to a unique binary but matched " +
                    std::to_string(paths.size()),
                ap.loc);
      }
    }

    if (bpftrace_.pid_ > 0) {
       USDTHelper::probes_for_pid(bpftrace_.pid_);
    } else if (ap.target != "") {
       USDTHelper::probes_for_path(ap.target);
    } else {
      error("usdt probe must specify at least path or pid to probe", ap.loc);
    }
  }
  else if (ap.provider == "tracepoint") {
    if (ap.target == "" || ap.func == "")
      error("tracepoint probe must have a target", ap.loc);
  }
  else if (ap.provider == "profile") {
    if (ap.target == "")
      error("profile probe must have unit of time", ap.loc);
    else if (ap.target != "hz" &&
             ap.target != "us" &&
             ap.target != "ms" &&
             ap.target != "s")
      error(ap.target + " is not an accepted unit of time", ap.loc);
    if (ap.func != "")
      error("profile probe must have an integer frequency", ap.loc);
    else if (ap.freq <= 0)
      error("profile frequency should be a positive integer", ap.loc);
  }
  else if (ap.provider == "interval") {
    if (ap.target == "")
      error("interval probe must have unit of time", ap.loc);
    else if (ap.target != "ms" &&
             ap.target != "s")
      error(ap.target + " is not an accepted unit of time", ap.loc);
    if (ap.func != "")
      error("interval probe must have an integer frequency", ap.loc);
  }
  else if (ap.provider == "software") {
    if (ap.target == "")
      error("software probe must have a software event name", ap.loc);
    else {
      bool found = false;
      for (auto &probeListItem : SW_PROBE_LIST) {
        if (ap.target == probeListItem.path || (!probeListItem.alias.empty() && ap.target == probeListItem.alias)) {
          found = true;
          break;
        }
      }
      if (!found)
        error(ap.target + " is not a software probe", ap.loc);
    }
    if (ap.func != "")
      error("software probe can only have an integer count", ap.loc);
    else if (ap.freq < 0)
      error("software count should be a positive integer", ap.loc);
  }
  else if (ap.provider == "watchpoint") {
    if (!ap.address)
      error("watchpoint must be attached to a non-zero address", ap.loc);
    if (ap.len != 1 && ap.len != 2 && ap.len != 4 && ap.len != 8)
      error("watchpoint length must be one of (1,2,4,8)", ap.loc);
    if (ap.mode.empty())
      error("watchpoint mode must be combination of (r,w,x)", ap.loc);
    std::sort(ap.mode.begin(), ap.mode.end());
    for (const char c : ap.mode) {
      if (c != 'r' && c != 'w' && c != 'x')
        error("watchpoint mode must be combination of (r,w,x)", ap.loc);
    }
    for (size_t i = 1; i < ap.mode.size(); ++i)
    {
      if (ap.mode[i - 1] == ap.mode[i])
        error("watchpoint modes may not be duplicated", ap.loc);
    }
    if (ap.mode == "rx" || ap.mode == "wx" || ap.mode == "rwx")
      error("watchpoint modes (rx, wx, rwx) not allowed", ap.loc);
  }
  else if (ap.provider == "hardware") {
    if (ap.target == "")
      error("hardware probe must have a hardware event name", ap.loc);
    else {
      bool found = false;
      for (auto &probeListItem : HW_PROBE_LIST) {
        if (ap.target == probeListItem.path || (!probeListItem.alias.empty() && ap.target == probeListItem.alias)) {
          found = true;
          break;
        }
      }
      if (!found)
        error(ap.target + " is not a hardware probe", ap.loc);
    }
    if (ap.func != "")
      error("hardware probe can only have an integer count", ap.loc);
    else if (ap.freq < 0)
      error("hardware frequency should be a positive integer", ap.loc);
  }
  else if (ap.provider == "BEGIN" || ap.provider == "END") {
    if (ap.target != "" || ap.func != "")
      error("BEGIN/END probes should not have a target", ap.loc);
    if (is_final_pass()) {
      if (ap.provider == "BEGIN") {
        if (has_begin_probe_)
          error("More than one BEGIN probe defined", ap.loc);
        has_begin_probe_ = true;
      }
      if (ap.provider == "END") {
        if (has_end_probe_)
          error("More than one END probe defined", ap.loc);
        has_end_probe_ = true;
      }
    }
  }
  else if (ap.provider == "kfunc" || ap.provider == "kretfunc")
  {
#ifdef HAVE_KFUNC
    bool supported = bpftrace_.btf_.has_data();
#else
    bool supported = false;
#endif

    if (!supported)
    {
      error("kfunc/kretfunc not available for your kernel version.", ap.loc);
      return;
    }

    const auto& ap_map = bpftrace_.btf_ap_args_;
    auto it = ap_map.find(ap.provider + ap.func);

    if (it != ap_map.end())
    {
      auto args = it->second;
      ap_args_.clear();
      ap_args_.insert(args.begin(), args.end());
    }
    else
    {
      error("Failed to resolve kfunc args.", ap.loc);
    }
  }
  else {
    ERR("Invalid provider: '" << ap.provider << "'", ap.loc);
  }
}

void SemanticAnalyser::visit(Probe &probe)
{
  // Clear out map of variable names - variables should be probe-local
  variable_val_.clear();
  probe_ = &probe;

  for (AttachPoint *ap : *probe.attach_points) {
    ap->accept(*this);
  }
  if (probe.pred) {
    probe.pred->accept(*this);
  }
  for (Statement *stmt : *probe.stmts) {
    stmt->accept(*this);
  }

}

void SemanticAnalyser::visit(Program &program)
{
  for (Probe *probe : *program.probes)
    probe->accept(*this);
}

int SemanticAnalyser::analyse()
{
  // Multiple passes to handle variables being used before they are defined
  std::string errors;

  for (pass_ = 1; pass_ <= num_passes_; pass_++) {
    root_->accept(*this);
    errors = err_.str();
    if (!errors.empty()) {
      out_ << errors;
      return pass_;
    }
  }

  return 0;
}

int SemanticAnalyser::create_maps(bool debug)
{
  uint32_t failed_maps = 0;
  auto is_invalid_map = [](int a) -> uint8_t { return a < 0 ? 1 : 0; };
  for (auto &map_val : map_val_)
  {
    std::string map_name = map_val.first;
    SizedType type = map_val.second;

    auto search_args = map_key_.find(map_name);
    if (search_args == map_key_.end())
    {
      out_ << "map key \"" << map_name << "\" not found" << std::endl;
      abort();
    }

    auto &key = search_args->second;

    if (debug)
    {
      bpftrace_.maps_[map_name] = std::make_unique<bpftrace::FakeMap>(map_name, type, key);
      bpftrace_.maps_[map_name]->id = bpftrace_.map_ids_.size();
      bpftrace_.map_ids_.push_back(map_name);
    }
    else
    {
      if (type.type == Type::lhist)
      {
        // store lhist args to the bpftrace::Map
        auto map_args = map_args_.find(map_name);
        if (map_args == map_args_.end())
        {
          out_ << "map arg \"" << map_name << "\" not found" << std::endl;
          abort();
        }

        Expression &min_arg = *map_args->second.at(1);
        Expression &max_arg = *map_args->second.at(2);
        Expression &step_arg = *map_args->second.at(3);
        Integer &min = static_cast<Integer&>(min_arg);
        Integer &max = static_cast<Integer&>(max_arg);
        Integer &step = static_cast<Integer&>(step_arg);
        bpftrace_.maps_[map_name] = std::make_unique<bpftrace::Map>(
            map_name, type, key, min.n, max.n, step.n, bpftrace_.mapmax_);
        bpftrace_.maps_[map_name]->id = bpftrace_.map_ids_.size();
        bpftrace_.map_ids_.push_back(map_name);
        failed_maps += is_invalid_map(bpftrace_.maps_[map_name]->mapfd_);
      }
      else
      {
        bpftrace_.maps_[map_name] = std::make_unique<bpftrace::Map>(
            map_name, type, key, bpftrace_.mapmax_);
        bpftrace_.maps_[map_name]->id = bpftrace_.map_ids_.size();
        bpftrace_.map_ids_.push_back(map_name);
        failed_maps += is_invalid_map(bpftrace_.maps_[map_name]->mapfd_);
      }
    }
  }

  for (StackType stack_type : needs_stackid_maps_) {
    // The stack type doesn't matter here, so we use kstack to force SizedType
    // to set stack_size.
    if (debug)
    {
      bpftrace_.stackid_maps_[stack_type] = std::make_unique<bpftrace::FakeMap>(SizedType(Type::kstack, stack_type));
    }
    else
    {
      bpftrace_.stackid_maps_[stack_type] = std::make_unique<bpftrace::Map>(SizedType(Type::kstack, stack_type));
      failed_maps += is_invalid_map(bpftrace_.stackid_maps_[stack_type]->mapfd_);
    }
  }

  if (debug)
  {
    if (needs_join_map_)
    {
      // join uses map storage as we'd like to process data larger than can fit on the BPF stack.
      std::string map_ident = "join";
      SizedType type = SizedType(Type::join, 8 + 8 + bpftrace_.join_argnum_ * bpftrace_.join_argsize_);
      MapKey key;
      bpftrace_.join_map_ = std::make_unique<bpftrace::FakeMap>(map_ident, type, key);
    }
    if (needs_elapsed_map_)
    {
      std::string map_ident = "elapsed";
      SizedType type = SizedType(Type::integer, 8);
      MapKey key;
      bpftrace_.elapsed_map_ =
          std::make_unique<bpftrace::FakeMap>(map_ident, type, key);
    }

    bpftrace_.perf_event_map_ = std::make_unique<bpftrace::FakeMap>(BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  }
  else
  {
    if (needs_join_map_)
    {
      // join uses map storage as we'd like to process data larger than can fit on the BPF stack.
      std::string map_ident = "join";
      SizedType type = SizedType(Type::join, 8 + 8 + bpftrace_.join_argnum_ * bpftrace_.join_argsize_);
      MapKey key;
      bpftrace_.join_map_ = std::make_unique<bpftrace::Map>(map_ident, type, key, 1);
      failed_maps += is_invalid_map(bpftrace_.join_map_->mapfd_);
    }
    if (needs_elapsed_map_)
    {
      std::string map_ident = "elapsed";
      SizedType type = SizedType(Type::integer, 8);
      MapKey key;
      bpftrace_.elapsed_map_ =
          std::make_unique<bpftrace::Map>(map_ident, type, key, 1);
      failed_maps += is_invalid_map(bpftrace_.elapsed_map_->mapfd_);
    }
    bpftrace_.perf_event_map_ = std::make_unique<bpftrace::Map>(BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    failed_maps += is_invalid_map(bpftrace_.perf_event_map_->mapfd_);
  }

  if (failed_maps > 0)
  {
    out_ << "Creation of the required BPF maps has failed." << std::endl;
    out_ << "Make sure you have all the required permissions and are not";
    out_ << " confined (e.g. like" << std::endl;
    out_ << "snapcraft does). `dmesg` will likely have useful output for";
    out_ << " further troubleshooting" << std::endl;
  }

  return failed_maps;
}

bool SemanticAnalyser::is_final_pass() const
{
  return pass_ == num_passes_;
}

bool SemanticAnalyser::check_assignment(const Call &call, bool want_map, bool want_var, bool want_map_key)
{
  if (want_map && want_var && want_map_key)
  {
    if (!call.map && !call.var && !call.key_for_map)
    {
      error(call.func + "() should be assigned to a map or a variable, or be "
                        "used as a map key",
            call.loc);
      return false;
    }
  }
  else if (want_map && want_var)
  {
    if (!call.map && !call.var)
    {
      error(call.func + "() should be assigned to a map or a variable",
            call.loc);
      return false;
    }
  }
  else if (want_map && want_map_key)
  {
    if (!call.map && !call.key_for_map)
    {
      error(call.func +
                "() should be assigned to a map or be used as a map key",
            call.loc);
      return false;
    }
  }
  else if (want_var && want_map_key)
  {
    if (!call.var && !call.key_for_map)
    {
      error(call.func +
                "() should be assigned to a variable or be used as a map key",
            call.loc);
      return false;
    }
  }
  else if (want_map)
  {
    if (!call.map)
    {
      error(call.func + "() should be assigned to a map", call.loc);
      return false;
    }
  }
  else if (want_var)
  {
    if (!call.var)
    {
      error(call.func + "() should be assigned to a variable", call.loc);
      return false;
    }
  }
  else if (want_map_key)
  {
    if (!call.key_for_map)
    {
      error(call.func + "() should be used as a map key", call.loc);
      return false;
    }
  }
  else
  {
    if (call.map || call.var || call.key_for_map)
    {
      error(call.func +
                "() should not be used in an assignment or as a map key",
            call.loc);
      return false;
    }
  }
  return true;
}

bool SemanticAnalyser::check_nargs(const Call &call, size_t expected_nargs)
{
  std::stringstream err;
  std::vector<Expression*>::size_type nargs = 0;
  if (call.vargs)
    nargs = call.vargs->size();

  if (nargs != expected_nargs)
  {
    if (expected_nargs == 0)
      err << call.func << "() requires no arguments";
    else if (expected_nargs == 1)
      err << call.func << "() requires one argument";
    else
      err << call.func << "() requires " << expected_nargs << " arguments";

    err << " (" << nargs << " provided)";
    error(err.str(), call.loc);
    return false;
  }
  return true;
}

bool SemanticAnalyser::check_varargs(const Call &call, size_t min_nargs, size_t max_nargs)
{
  std::vector<Expression*>::size_type nargs = 0;
  std::stringstream err;
  if (call.vargs)
    nargs = call.vargs->size();

  if (nargs < min_nargs)
  {
    if (min_nargs == 1)
      err << call.func << "() requires at least one argument";
    else
      err << call.func << "() requires at least " << min_nargs << " arguments";

    err << " (" << nargs << " provided)";
    error(err.str(), call.loc);
    return false;
  }
  else if (nargs > max_nargs)
  {
    if (max_nargs == 0)
      err << call.func << "() requires no arguments";
    else if (max_nargs == 1)
      err << call.func << "() takes up to one argument";
    else
      err << call.func << "() takes up to " << max_nargs << " arguments";

    err << " (" << nargs << " provided)";
    error(err.str(), call.loc);
    return false;
  }

  return true;
}

bool SemanticAnalyser::check_arg(const Call &call, Type type, int arg_num, bool want_literal)
{
  if (!call.vargs)
    return false;

  auto &arg = *call.vargs->at(arg_num);
  if (want_literal && (!arg.is_literal || arg.type.type != type))
  {
    ERR(call.func << "() expects a " << type
                  << " literal"
                     " ("
                  << arg.type.type << " provided)",
        call.loc);
    return false;
  }
  else if (is_final_pass() && arg.type.type != type) {
    ERR(call.func << "() only supports " << type << " arguments"
                  << " (" << arg.type.type << " provided)",
        call.loc);
    return false;
  }
  return true;
}

bool SemanticAnalyser::check_symbol(const Call &call, int arg_num __attribute__((unused)))
{
  if (!call.vargs)
    return false;

  auto &arg = static_cast<String&>(*call.vargs->at(0)).str;

  std::string re = "^[a-zA-Z0-9./_-]+$";
  bool is_valid = std::regex_match(arg, std::regex(re));
  if (!is_valid)
  {
    ERR(call.func << "() expects a string that is a valid symbol (" << re
                  << ") as input"
                  << " (\"" << arg << "\" provided)",
        call.loc);
    return false;
  }

  return true;
}

/*
 * assign_map_type
 *
 *   Semantic analysis for assigning a value of the provided type
 *   to the given map.
 */
void SemanticAnalyser::assign_map_type(const Map &map, const SizedType &type)
{
  const std::string &map_ident = map.ident;
  auto search = map_val_.find(map_ident);
  if (search != map_val_.end()) {
    if (search->second.type == Type::none) {
      if (is_final_pass()) {
        error("Undefined map: " + map_ident, map.loc);
      }
      else {
        search->second = type;
      }
    }
    else if (search->second.type != type.type) {
      ERR("Type mismatch for "
              << map_ident << ": "
              << "trying to assign value of type '" << type
              << "' when map already contains a value of type '"
              << search->second,
          map.loc);
    }
  }
  else {
    // This map hasn't been seen before
    map_val_.insert({map_ident, type});
    if (map_val_[map_ident].type == Type::integer) {
      // Store all integer values as 64-bit in maps, so that there will
      // be space for any integer to be assigned to the map later
      map_val_[map_ident].size = 8;
    }
  }
}

} // namespace ast
} // namespace bpftrace
