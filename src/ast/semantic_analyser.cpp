#include "semantic_analyser.h"
#include "arch/arch.h"
#include "ast.h"
#include "fake_map.h"
#include "log.h"
#include "parser.tab.hh"
#include "printf.h"
#include "probe_matcher.h"
#include "signal_bt.h"
#include "tracepoint_format_parser.h"
#include "usdt.h"
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
    { "uint8", std::tuple<size_t, bool>{ 8, false } },
    { "int8", std::tuple<size_t, bool>{ 8, true } },
    { "uint16", std::tuple<size_t, bool>{ 16, false } },
    { "int16", std::tuple<size_t, bool>{ 16, true } },
    { "uint32", std::tuple<size_t, bool>{ 32, false } },
    { "int32", std::tuple<size_t, bool>{ 32, true } },
    { "uint64", std::tuple<size_t, bool>{ 64, false } },
    { "int64", std::tuple<size_t, bool>{ 64, true } },
  };
  return intcasts;
}

void SemanticAnalyser::visit(Integer &integer)
{
  integer.type = CreateInt64();
}

void SemanticAnalyser::visit(PositionalParameter &param)
{
  param.type = CreateInt64();
  if (func_ == "str")
  {
    param.is_in_str = true;
    has_pos_param_ = true;
  }
  switch (param.ptype)
  {
    case PositionalParameterType::positional:
      if (param.n <= 0)
        LOG(ERROR, param.loc, err_)
            << "$" << std::to_string(param.n) + " is not a valid parameter";
      if (is_final_pass()) {
        std::string pstr = bpftrace_.get_param(param.n, param.is_in_str);
        if (!is_numeric(pstr) && !param.is_in_str)
        {
          LOG(ERROR, param.loc, err_)
              << "$" << param.n << " used numerically but given \"" << pstr
              << "\". Try using str($" << param.n << ").";
        }
        // string allocated in bpf stack. See codegen.
        if (param.is_in_str)
          param.type.SetAS(AddrSpace::kernel);
      }
      break;
    case PositionalParameterType::count:
      if (param.is_in_str)
      {
        LOG(ERROR, param.loc, err_) << "use $#, not str($#)";
      }
      break;
    default:
      LOG(ERROR, param.loc, err_) << "unknown parameter type";
      param.type = CreateNone();
      break;
  }
}

void SemanticAnalyser::visit(String &string)
{
  // Skip check for printf()'s format string (1st argument) and create the
  // string with the original size. This is because format string is not part of
  // bpf byte code.
  if (func_ == "printf" && func_arg_idx_ == 0)
  {
    string.type = CreateString(string.str.size());
    return;
  }

  if (!is_compile_time_func(func_) && string.str.size() > STRING_SIZE - 1)
  {
    LOG(ERROR, string.loc, err_) << "String is too long (over " << STRING_SIZE
                                 << " bytes): " << string.str;
  }
  string.type = CreateString(STRING_SIZE);
  // @a = buf("hi", 2). String allocated on bpf stack. See codegen
  string.type.SetAS(AddrSpace::kernel);
}

void SemanticAnalyser::visit(StackMode &mode)
{
  mode.type = CreateStackMode();
  if (mode.mode == "bpftrace") {
    mode.type.stack_type.mode = bpftrace::StackMode::bpftrace;
  } else if (mode.mode == "perf") {
    mode.type.stack_type.mode = bpftrace::StackMode::perf;
  } else {
    mode.type = CreateNone();
    LOG(ERROR, mode.loc, err_) << "Unknown stack mode: '" + mode.mode + "'";
  }
}

void SemanticAnalyser::visit(Identifier &identifier)
{
  if (bpftrace_.enums_.count(identifier.ident) != 0) {
    identifier.type = CreateUInt64();
  }
  else if (bpftrace_.structs.Has(identifier.ident))
  {
    identifier.type = CreateRecord(identifier.ident,
                                   bpftrace_.structs.Lookup(identifier.ident));
  }
  else if (func_ == "sizeof" && getIntcasts().count(identifier.ident) != 0)
  {
    identifier.type = CreateInt(
        std::get<0>(getIntcasts().at(identifier.ident)));
  }
  else {
    identifier.type = CreateNone();
    LOG(ERROR, identifier.loc, err_)
        << "Unknown identifier: '" + identifier.ident + "'";
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
  auto matches = bpftrace_.probe_matcher_->get_matches_for_ap(*attach_point);
  if (!matches.empty())
  {
    auto &match = *matches.begin();
    std::string tracepoint_struct = TracepointFormatParser::get_struct_name(
        match);
    AddrSpace as = (attach_point->target == "syscalls") ? AddrSpace::user
                                                        : AddrSpace::kernel;
    builtin.type = CreatePointer(CreateRecord(tracepoint_struct,
                                              bpftrace_.structs.Lookup(
                                                  tracepoint_struct)),
                                 as);
    builtin.type.MarkCtxAccess();
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

AddrSpace SemanticAnalyser::find_addrspace(ProbeType pt)
{
  switch (pt)
  {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
    case ProbeType::kfunc:
    case ProbeType::kretfunc:
    case ProbeType::tracepoint:
    case ProbeType::iter:
      return AddrSpace::kernel;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::usdt:
      return AddrSpace::user;
    // case : i:ms:1 (struct x*)ctx)->x
    // Cannot decide the addrspace. Provide backward compatibility,
    // if addrspace cannot be detected.
    case ProbeType::invalid:
    case ProbeType::profile:
    case ProbeType::interval:
    case ProbeType::software:
    case ProbeType::hardware:
    case ProbeType::watchpoint:
    case ProbeType::asyncwatchpoint:
      // Will trigger a warning in selectProbeReadHelper.
      return AddrSpace::none;
  }
  return {}; // unreached
}

void SemanticAnalyser::visit(Builtin &builtin)
{
  if (builtin.ident == "ctx")
  {
    ProbeType pt = probetype((*probe_->attach_points)[0]->provider);
    bpf_prog_type bt = progtype(pt);
    std::string func = (*probe_->attach_points)[0]->func;

    for (auto &attach_point : *probe_->attach_points)
    {
      ProbeType pt = probetype(attach_point->provider);
      bpf_prog_type bt2 = progtype(pt);
      if (bt != bt2)
        LOG(ERROR, builtin.loc, err_)
            << "ctx cannot be used in different BPF program types: "
            << progtypeName(bt) << " and " << progtypeName(bt2);
    }
    switch (static_cast<libbpf::bpf_prog_type>(bt))
    {
      case libbpf::BPF_PROG_TYPE_KPROBE:
        builtin.type = CreatePointer(CreateRecord("struct pt_regs",
                                                  bpftrace_.structs.Lookup(
                                                      "structs pt_regs")),
                                     AddrSpace::kernel);
        builtin.type.MarkCtxAccess();
        break;
      case libbpf::BPF_PROG_TYPE_TRACEPOINT:
        LOG(ERROR, builtin.loc, err_)
            << "Use args instead of ctx in tracepoint";
        break;
      case libbpf::BPF_PROG_TYPE_PERF_EVENT:
        builtin.type = CreatePointer(
            CreateRecord("struct bpf_perf_event_data",
                         bpftrace_.structs.Lookup(
                             "struct bpf_perf_event_data")),
            AddrSpace::kernel);
        builtin.type.MarkCtxAccess();
        break;
      case libbpf::BPF_PROG_TYPE_TRACING:
        if (pt == ProbeType::iter)
        {
          std::string type;

          if (func == "task")
          {
            type = "struct bpf_iter__task";
          }
          else if (func == "task_file")
          {
            type = "struct bpf_iter__task_file";
          }
          else
          {
            LOG(ERROR, builtin.loc, err_) << "unsupported iter type: " << func;
          }

          builtin.type = CreatePointer(
              CreateRecord(type, bpftrace_.structs.Lookup(type)),
              AddrSpace::kernel);
          builtin.type.MarkCtxAccess();
        }
        else
        {
          LOG(ERROR, builtin.loc, err_) << "invalid program type";
        }
        break;
      default:
        LOG(ERROR, builtin.loc, err_) << "invalid program type";
        break;
    }
  }
  else if (builtin.ident == "nsecs" || builtin.ident == "elapsed" ||
           builtin.ident == "pid" || builtin.ident == "tid" ||
           builtin.ident == "cgroup" || builtin.ident == "uid" ||
           builtin.ident == "gid" || builtin.ident == "cpu" ||
           builtin.ident == "rand")
  {
    builtin.type = CreateUInt64();
    if (builtin.ident == "cgroup" &&
        !bpftrace_.feature_->has_helper_get_current_cgroup_id())
    {
      LOG(ERROR, builtin.loc, err_)
          << "BPF_FUNC_get_current_cgroup_id is not available for your kernel "
             "version";
    }
  }
  else if (builtin.ident == "curtask")
  {
    /*
     * Retype curtask to its original type: struct task_struct.
     */
    builtin.type = CreatePointer(CreateRecord("struct task_struct",
                                              bpftrace_.structs.Lookup(
                                                  "struct task_struct")),
                                 AddrSpace::kernel);
  }
  else if (builtin.ident == "retval")
  {
    ProbeType type = single_provider_type();

    if (type == ProbeType::kretprobe || type == ProbeType::uretprobe)
    {
      builtin.type = CreateUInt64();
    }
    else if (type == ProbeType::kfunc || type == ProbeType::kretfunc)
    {
      auto it = ap_args_.find("$retval");

      if (it != ap_args_.end())
        builtin.type = it->second;
      else
        LOG(ERROR, builtin.loc, err_) << "Can't find a field $retval";
    }
    else
    {
      LOG(ERROR, builtin.loc, err_)
          << "The retval builtin can only be used with 'kretprobe' and "
          << "'uretprobe' and 'kfunc' probes"
          << (type == ProbeType::tracepoint ? " (try to use args->ret instead)"
                                            : "");
    }
    // For kretprobe, kfunc, kretfunc -> AddrSpace::kernel
    // For uretprobe -> AddrSpace::user
    builtin.type.SetAS(find_addrspace(type));
  }
  else if (builtin.ident == "kstack") {
    builtin.type = CreateStack(true, StackType());
  }
  else if (builtin.ident == "ustack") {
    builtin.type = CreateStack(false, StackType());
  }
  else if (builtin.ident == "comm") {
    builtin.type = CreateString(COMM_SIZE);
    // comm allocated in the bpf stack. See codegen
    // Case: @=comm and strncmp(@, "name")
    builtin.type.SetAS(AddrSpace::kernel);
  }
  else if (builtin.ident == "func") {
    for (auto &attach_point : *probe_->attach_points)
    {
      ProbeType type = probetype(attach_point->provider);
      if (type == ProbeType::kprobe ||
          type == ProbeType::kretprobe)
        builtin.type = CreateKSym();
      else if (type == ProbeType::uprobe || type == ProbeType::uretprobe)
        builtin.type = CreateUSym();
      else
        LOG(ERROR, builtin.loc, err_)
            << "The func builtin can not be used with '"
            << attach_point->provider << "' probes";
    }
  }
  else if (!builtin.ident.compare(0, 3, "arg") && builtin.ident.size() == 4 &&
      builtin.ident.at(3) >= '0' && builtin.ident.at(3) <= '9') {
    ProbeType pt = probetype((*probe_->attach_points)[0]->provider);
    AddrSpace addrspace = find_addrspace(pt);
    for (auto &attach_point : *probe_->attach_points)
    {
      ProbeType type = probetype(attach_point->provider);
      if (type != ProbeType::kprobe &&
          type != ProbeType::uprobe &&
          type != ProbeType::usdt)
        LOG(ERROR, builtin.loc, err_)
            << "The " << builtin.ident << " builtin can only be used with "
            << "'kprobes', 'uprobes' and 'usdt' probes";
    }
    int arg_num = atoi(builtin.ident.substr(3).c_str());
    if (arg_num > arch::max_arg())
      LOG(ERROR, builtin.loc, err_)
          << arch::name() << " doesn't support " << builtin.ident;
    builtin.type = CreateUInt64();
    builtin.type.SetAS(addrspace);
  }
  else if (!builtin.ident.compare(0, 4, "sarg") && builtin.ident.size() == 5 &&
      builtin.ident.at(4) >= '0' && builtin.ident.at(4) <= '9') {
    ProbeType pt = probetype((*probe_->attach_points)[0]->provider);
    AddrSpace addrspace = find_addrspace(pt);
    for (auto &attach_point : *probe_->attach_points)
    {
      ProbeType type = probetype(attach_point->provider);
      if (type != ProbeType::kprobe && type != ProbeType::uprobe)
        LOG(ERROR, builtin.loc, err_)
            << "The " + builtin.ident
            << " builtin can only be used with 'kprobes' and 'uprobes' probes";
      if (is_final_pass() &&
          (attach_point->address != 0 || attach_point->func_offset != 0)) {
        // If sargX values are needed when using an offset, they can be stored in a map
        // when entering the function and then referenced from an offset-based probe
        LOG(WARNING, builtin.loc, out_)
            << "Using an address offset with the sargX built-in can"
               "lead to unexpected behavior ";
      }
    }
    builtin.type = CreateUInt64();
    builtin.type.SetAS(addrspace);
  }
  else if (builtin.ident == "probe") {
    builtin.type = CreateProbe();
    probe_->need_expansion = true;
  }
  else if (builtin.ident == "username") {
    builtin.type = CreateUsername();
  }
  else if (builtin.ident == "cpid") {
    if (!has_child_)
    {
      LOG(ERROR, builtin.loc, err_)
          << "cpid cannot be used without child command";
    }
    builtin.type = CreateUInt32();
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
      builtin.type = CreatePointer(CreateRecord("struct kfunc",
                                                bpftrace_.structs.Lookup(
                                                    "struct kfunc")),
                                   AddrSpace::kernel);
      builtin.type.MarkCtxAccess();
      builtin.type.is_kfarg = true;
    }
    else
    {
      LOG(ERROR, builtin.loc, err_)
          << "The args builtin can only be used with tracepoint/kfunc probes ("
          << probetypeName(type) << " used here)";
    }
  }
  else {
    builtin.type = CreateNone();
    LOG(ERROR, builtin.loc, err_)
        << "Unknown builtin variable: '" << builtin.ident << "'";
  }
}

void SemanticAnalyser::visit(Call &call)
{
  // Check for unsafe-ness first. It is likely the most pertinent issue
  // (and should be at the top) for any function call.
  if (bpftrace_.safe_mode_ && is_unsafe_func(call.func)) {
    LOG(ERROR, call.loc, err_)
        << call.func << "() is an unsafe function being used in safe mode";
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
      analyser_.func_arg_idx_ = -1;
    }

  private:
    SemanticAnalyser &analyser_;
    std::string old_func_;
  };

  func_setter scope_bound_func_setter{ *this, call.func };

  if (call.vargs) {
    for (size_t i = 0; i < call.vargs->size(); ++i)
    {
      auto &expr = (*call.vargs)[i];
      func_arg_idx_ = i;

      expr->accept(*this);
    }
  }

  for (auto &ap : *probe_->attach_points)
  {
    if (!check_available(call, *ap))
    {
      LOG(ERROR, call.loc, err_) << call.func << " can not be used with \""
                                 << ap->provider << "\" probes";
    }
  }

  if (call.func == "hist") {
    check_assignment(call, true, false, false);
    check_nargs(call, 1);
    check_arg(call, Type::integer, 0);

    call.type = CreateHist();
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
        LOG(ERROR, call.loc, err_)
            << "lhist() step must be >= 1 (" << step.n << " provided)";
      }
      else
      {
        int buckets = (max.n - min.n) / step.n;
        if (buckets > 1000)
        {
          LOG(ERROR, call.loc, err_)
              << "lhist() too many buckets, must be <= 1000 (would need "
              << buckets << ")";
        }
      }
      if (min.n < 0)
      {
        LOG(ERROR, call.loc, err_)
            << "lhist() min must be non-negative (provided min " << min.n
            << ")";
      }
      if (min.n > max.n)
      {
        LOG(ERROR, call.loc, err_)
            << "lhist() min must be less than max (provided min " << min.n
            << " and max ";
      }
      if ((max.n - min.n) < step.n)
      {
        LOG(ERROR, call.loc, err_)
            << "lhist() step is too large for the given range (provided step "
            << step.n << " for range " << (max.n - min.n) << ")";
      }
    }
    call.type = CreateLhist();
  }
  else if (call.func == "count") {
    check_assignment(call, true, false, false);
    check_nargs(call, 0);

    call.type = CreateCount(true);
  }
  else if (call.func == "sum") {
    bool sign = false;
    check_assignment(call, true, false, false);
    if (check_nargs(call, 1)) {
      check_arg(call, Type::integer, 0);
      sign = call.vargs->at(0)->type.IsSigned();
    }
    call.type = CreateSum(sign);
  }
  else if (call.func == "min") {
    bool sign = false;
    check_assignment(call, true, false, false);
    if (check_nargs(call, 1)) {
      check_arg(call, Type::integer, 0);
      sign = call.vargs->at(0)->type.IsSigned();
    }
    call.type = CreateMin(sign);
  }
  else if (call.func == "max") {
    bool sign = false;
    check_assignment(call, true, false, false);
    if (check_nargs(call, 1)) {
      check_arg(call, Type::integer, 0);
      sign = call.vargs->at(0)->type.IsSigned();
    }
    call.type = CreateMax(sign);
  }
  else if (call.func == "avg") {
    check_assignment(call, true, false, false);
    check_nargs(call, 1);
    check_arg(call, Type::integer, 0);
    call.type = CreateAvg(true);
  }
  else if (call.func == "stats") {
    check_assignment(call, true, false, false);
    check_nargs(call, 1);
    check_arg(call, Type::integer, 0);
    call.type = CreateStats(true);
  }
  else if (call.func == "delete") {
    check_assignment(call, false, false, false);
    if (check_nargs(call, 1)) {
      auto &arg = *call.vargs->at(0);
      if (!arg.is_map)
        LOG(ERROR, call.loc, err_) << "delete() expects a map to be provided";
    }

    call.type = CreateNone();
  }
  else if (call.func == "str") {
    if (check_varargs(call, 1, 2)) {
      auto *arg = call.vargs->at(0);
      auto &t = arg->type;
      if (!t.IsIntegerTy() && !t.IsPtrTy())
      {
        LOG(ERROR, call.loc, err_)
            << call.func << "() expects an integer or a pointer type as first "
            << "argument (" << t << " provided)";
      }
      call.type = CreateString(bpftrace_.strlen_);
      if (has_pos_param_)
      {
        if (dynamic_cast<PositionalParameter *>(arg))
          call.is_literal = true;
        else
        {
          auto binop = dynamic_cast<Binop *>(arg);
          if (!(binop && (dynamic_cast<PositionalParameter *>(binop->left) ||
                          dynamic_cast<PositionalParameter *>(binop->right))))
          {
            // Only str($1), str($1 + CONST), or str(CONST + $1) are allowed
            LOG(ERROR, call.loc, err_)
                << call.func << "() only accepts positional parameters"
                << " directly or with a single constant offset added";
          }
        }
      }

      if (is_final_pass() && call.vargs->size() == 2 &&
          check_arg(call, Type::integer, 1, false))
      {
        auto &size_arg = *call.vargs->at(1);
        if (size_arg.is_literal)
        {
          auto &integer = static_cast<Integer &>(size_arg);
          long value = integer.n;
          if (value < 0)
            LOG(ERROR, call.loc, err_)
                << call.func << "cannot use negative length (" << value << ")";
        }
      }

      // Required for cases like strncmp(str($1), str(2), 4))
      call.type.SetAS(t.GetAS());
    }
    has_pos_param_ = false;
  }
  else if (call.func == "buf")
  {
    if (!check_varargs(call, 1, 2))
      return;

    auto &arg = *call.vargs->at(0);
    if (is_final_pass() && !(arg.type.IsIntTy() || arg.type.IsStringTy() ||
                             arg.type.IsPtrTy() || arg.type.IsArrayTy()))
    {
      LOG(ERROR, call.loc, err_)
          << call.func
          << "() expects an integer, string, or array argument but saw "
          << typestr(arg.type.type);
    }

    size_t max_buffer_size = bpftrace_.strlen_;
    size_t buffer_size = max_buffer_size;

    if (call.vargs->size() == 1)
    {
      if (arg.type.IsArrayTy())
        buffer_size = arg.type.GetNumElements() *
                      arg.type.GetElementTy()->GetSize();
      else if (is_final_pass())
        LOG(ERROR, call.loc, err_)
            << call.func << "() expects a length argument for non-array type "
            << typestr(arg.type.type);
    }
    else
    {
      if (is_final_pass())
        check_arg(call, Type::integer, 1, false);

      auto &size_arg = *call.vargs->at(1);
      if (size_arg.is_literal)
      {
        auto *integer = dynamic_cast<Integer *>(&size_arg);
        if (integer)
        {
          long value = integer->n;
          if (value < 0)
          {
            LOG(ERROR, call.loc, err_)
                << call.func << " cannot use negative length (" << value << ")";
          }
          buffer_size = value;
        }
      }
    }

    if (buffer_size > max_buffer_size)
    {
      if (is_final_pass())
        LOG(WARNING, call.loc, out_)
            << call.func << "() length is too long and will be shortened to "
            << std::to_string(bpftrace_.strlen_)
            << " bytes (see BPFTRACE_STRLEN)";

      buffer_size = max_buffer_size;
    }

    buffer_size++; // extra byte is used to embed the length of the buffer
    call.type = CreateBuffer(buffer_size);
    // Consider case : $a = buf("hi", 2); $b = buf("bye", 3);  $a == $b
    // The result of buf is copied to bpf stack. Hence kernel probe read
    call.type.SetAS(AddrSpace::kernel);
  }
  else if (call.func == "ksym" || call.func == "usym") {
    if (check_nargs(call, 1)) {
      // allow symbol lookups on casts (eg, function pointers)
      auto &arg = *call.vargs->at(0);
      auto &type = arg.type;
      if (!type.IsIntegerTy() && !type.IsPtrTy())
        LOG(ERROR, call.loc, err_)
            << call.func << "() expects an integer or pointer argument";
    }

    if (call.func == "ksym")
      call.type = CreateKSym();
    else if (call.func == "usym")
      call.type = CreateUSym();
  }
  else if (call.func == "ntop") {
    if (!check_varargs(call, 1, 2))
      return;

    auto arg = call.vargs->at(0);
    if (call.vargs->size() == 2) {
      arg = call.vargs->at(1);
      check_arg(call, Type::integer, 0);
    }

    if (!arg->type.IsIntTy() && !arg->type.IsStringTy() &&
        !arg->type.IsArrayTy())
      LOG(ERROR, call.loc, err_)
          << call.func << "() expects an integer or array argument, got "
          << arg->type.type;

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
    auto type = arg->type;

    if ((arg->type.IsArrayTy() || arg->type.IsStringTy()) &&
        type.GetSize() != 4 && type.GetSize() != 16)
      LOG(ERROR, call.loc, err_)
          << call.func << "() argument must be 4 or 16 bytes in size";

    call.type = CreateInet(buffer_size);
  }
  else if (call.func == "join") {
    check_assignment(call, false, false, false);
    call.type = CreateNone();

    if (!check_varargs(call, 1, 2))
      return;

    if (!is_final_pass())
      return;

    auto &arg = *call.vargs->at(0);
    if (!(arg.type.IsIntTy() || arg.type.IsPtrTy()))
    {
      LOG(ERROR, call.loc, err_) << "() only supports int or pointer arguments"
                                 << " (" << arg.type.type << " provided)";
    }

    if (call.vargs && call.vargs->size() > 1)
      check_arg(call, Type::string, 1, true);
  }
  else if (call.func == "reg") {
    if (check_nargs(call, 1)) {
      if (check_arg(call, Type::string, 0, true)) {
        auto reg_name = bpftrace_.get_string_literal(call.vargs->at(0));
        int offset = arch::offset(reg_name);;
        if (offset == -1) {
          LOG(ERROR, call.loc, err_)
              << "'" << reg_name
              << "' is not a valid register on this architecture"
              << " (" << arch::name() << ")";
        }
      }
    }
    call.type = CreateUInt64();
    ProbeType pt = single_provider_type();
    // In case of different attach_points, Set the addrspace to none.
    call.type.SetAS(find_addrspace(pt));
  }
  else if (call.func == "kaddr") {
    if (check_nargs(call, 1)) {
      check_arg(call, Type::string, 0, true);
    }
    call.type = CreateUInt64();
    call.type.SetAS(AddrSpace::kernel);
  }
  else if (call.func == "uaddr")
  {
    if (!check_nargs(call, 1))
      return;
    if (!(check_arg(call, Type::string, 0, true) && check_symbol(call, 0)))
      return;

    std::vector<int> sizes;
    auto name = bpftrace_.get_string_literal(call.vargs->at(0));
    for (auto &ap : *probe_->attach_points)
    {
      struct symbol sym = {};
      int err = bpftrace_.resolve_uname(name, &sym, ap->target);
      if (err < 0 || sym.address == 0)
      {
        LOG(ERROR, call.loc, err_)
            << "Could not resolve symbol: " << ap->target << ":" << name;
      }
      sizes.push_back(sym.size);
    }

    for (size_t i = 1; i < sizes.size(); i++)
    {
      if (sizes.at(0) != sizes.at(i))
      {
        LOG(ERROR, call.loc, err_)
            << "Symbol size mismatch between probes. Symbol \"" << name
            << "\" has size " << sizes.at(0) << " for probe \""
            << probe_->attach_points->at(0)->name("") << "\" but size "
            << sizes.at(i) << " for probe \""
            << probe_->attach_points->at(i)->name("") << "\"";
      }
    }
    size_t pointee_size = 0;
    switch (sizes.at(0))
    {
      case 1:
      case 2:
      case 4:
        pointee_size = sizes.at(0) * 8;
        break;
      default:
        pointee_size = 64;
    }
    call.type = CreatePointer(CreateInt(pointee_size), AddrSpace::user);
  }
  else if (call.func == "cgroupid") {
    if (check_nargs(call, 1)) {
      check_arg(call, Type::string, 0, true);
    }
    call.type = CreateUInt64();
  }
  else if (call.func == "printf" || call.func == "system" || call.func == "cat")
  {
    check_assignment(call, false, false, false);
    if (check_varargs(call, 1, 128))
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
          // NOTE: modifying the type will break the resizing that happens
          // in the codegen. We have to copy the type here to avoid modification
          SizedType ty = (*iter)->type;
          // Promote to 64-bit if it's not an aggregate type
          if (!ty.IsAggregate() && !ty.IsTimestampTy())
            ty.SetSize(8);
          args.push_back(Field{
              .name = "",
              .type = ty,
              .offset = 0,
              .is_bitfield = false,
              .bitfield =
                  Bitfield{
                      .read_bytes = 0,
                      .access_rshift = 0,
                      .mask = 0,
                  },
          });
        }
        std::string msg = verify_format_string(fmt.str, args);
        if (msg != "")
        {
          LOG(ERROR, call.loc, err_) << msg;
        }
      }
    }

    call.type = CreateNone();
  }
  else if (call.func == "exit") {
    check_assignment(call, false, false, false);
    check_nargs(call, 0);
  }
  else if (call.func == "print") {
    check_assignment(call, false, false, false);
    if (in_loop() && is_final_pass())
    {
      LOG(WARNING, call.loc, out_)
          << "Due to it's asynchronous nature using 'print()' in a loop can "
             "lead to unexpected behavior. The map will likely be updated "
             "before the runtime can 'print' it.";
    }
    if (check_varargs(call, 1, 3)) {
      auto &arg = *call.vargs->at(0);
      if (arg.is_map)
      {
        Map &map = static_cast<Map&>(arg);
        map.skip_key_validation = true;
        if (map.vargs != nullptr) {
          LOG(ERROR, call.loc, err_)
              << "The map passed to " << call.func << "() should not be "
              << "indexed by a key";
        }

        if (is_final_pass())
        {
          if (call.vargs->size() > 1)
            check_arg(call, Type::integer, 1, true);
          if (call.vargs->size() > 2)
            check_arg(call, Type::integer, 2, true);
          if (map.type.IsStatsTy() && call.vargs->size() > 1)
          {
            LOG(WARNING, call.loc, out_)
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
      // min(), max(), etc. to be assigned directly to a map. This ensures that
      // the previous `arg.is_map` arm is hit first.
      else if (arg.type.IsPrintableTy())
      {
        if (call.vargs->size() != 1)
          LOG(ERROR, call.loc, err_)
              << "Non-map print() only takes 1 argument, " << call.vargs->size()
              << " found";
      }
      else
      {
        if (is_final_pass())
          LOG(ERROR, call.loc, err_) << arg.type << " type passed to "
                                     << call.func << "() is not printable";
      }
    }
  }
  else if (call.func == "clear") {
    check_assignment(call, false, false, false);
    if (check_nargs(call, 1)) {
      auto &arg = *call.vargs->at(0);
      if (!arg.is_map)
        LOG(ERROR, call.loc, err_) << "clear() expects a map to be provided";
      else {
        Map &map = static_cast<Map&>(arg);
        map.skip_key_validation = true;
        if (map.vargs != nullptr) {
          LOG(ERROR, call.loc, err_)
              << "The map passed to " << call.func << "() should not be "
              << "indexed by a key";
        }
      }
    }
  }
  else if (call.func == "zero") {
    check_assignment(call, false, false, false);
    if (check_nargs(call, 1)) {
      auto &arg = *call.vargs->at(0);
      if (!arg.is_map)
        LOG(ERROR, call.loc, err_) << "zero() expects a map to be provided";
      else {
        Map &map = static_cast<Map&>(arg);
        map.skip_key_validation = true;
        if (map.vargs != nullptr) {
          LOG(ERROR, call.loc, err_)
              << "The map passed to " << call.func << "() should not be "
              << "indexed by a key";
        }
      }
    }
  }
  else if (call.func == "time") {
    check_assignment(call, false, false, false);
    if (check_varargs(call, 0, 1)) {
      if (is_final_pass()) {
        if (call.vargs && call.vargs->size() > 0)
          check_arg(call, Type::string, 0, true);
      }
    }
  }
  else if (call.func == "strftime")
  {
    call.type = CreateTimestamp();
    check_varargs(call, 2, 2) && is_final_pass() &&
        check_arg(call, Type::string, 0, true) &&
        check_arg(call, Type::integer, 1, false);
  }
  else if (call.func == "kstack") {
    check_stack_call(call, true);
  }
  else if (call.func == "ustack") {
    check_stack_call(call, false);
  }
  else if (call.func == "signal") {
    if (!bpftrace_.feature_->has_helper_send_signal())
    {
      LOG(ERROR, call.loc, err_)
          << "BPF_FUNC_send_signal not available for your kernel version";
    }

    check_assignment(call, false, false, false);

    if (!check_varargs(call, 1, 1)) {
      return;
    }

    auto &arg = *call.vargs->at(0);
    if (arg.type.IsStringTy() && arg.is_literal)
    {
      auto sig = bpftrace_.get_string_literal(&arg);
      if (signal_name_to_num(sig) < 1) {
        LOG(ERROR, call.loc, err_) << sig << " is not a valid signal";
      }
    }
    else if (arg.type.IsIntTy() && arg.is_literal)
    {
      auto sig = static_cast<Integer&>(arg).n;
      if (sig < 1 || sig > 64) {
        LOG(ERROR, call.loc, err_)
            << std::to_string(sig)
            << " is not a valid signal, allowed range: [1,64]";
      }
    }
    else if(arg.type.type != Type::integer) {
      LOG(ERROR, call.loc, err_)
          << "signal only accepts string literals or integers";
    }
  }
  else if (call.func == "sizeof")
  {
    // sizeof() is a interesting builtin because the arguments can be either
    // an expression or a type. As a result, the only thing we'll check here
    // is that we have a single argument.
    check_nargs(call, 1);

    call.type = CreateUInt64();
  }
  else if (call.func == "path")
  {
    if (!bpftrace_.feature_->has_d_path())
    {
      LOG(ERROR, call.loc, err_)
          << "BPF_FUNC_d_path not available for your kernel version";
    }

    if (check_varargs(call, 1, 1))
    {
      // Argument for path can be both record and pointer.
      // It's pointer when it's passed directly from the probe
      // argument, like: path(args->path))
      // It's record when it's referenced as object pointer
      // member, like: path(args->filp->f_path))
      if (!check_arg(call, Type::record, 0, false, false) &&
          !check_arg(call, Type::pointer, 0, false, false))
      {
        auto &arg = *call.vargs->at(0);

        LOG(ERROR, call.loc, err_)
            << "path() only supports pointer or record argument ("
            << arg.type.type << " provided)";
      }

      call.type = SizedType(Type::string, bpftrace_.strlen_);
    }

    for (auto &attach_point : *probe_->attach_points)
    {
      ProbeType type = probetype(attach_point->provider);
      if (type != ProbeType::kfunc && type != ProbeType::kretfunc &&
          type != ProbeType::iter)
        LOG(ERROR, call.loc, err_) << "The path function can only be used with "
                                   << "'kfunc', 'kretfunc', 'iter' probes";
    }
  }
  else if (call.func == "strncmp") {
    if (check_nargs(call, 3)) {
      check_arg(call, Type::string, 0);
      check_arg(call, Type::string, 1);
      if (check_arg(call, Type::integer, 2, true)){
        Integer &size = static_cast<Integer&>(*call.vargs->at(2));
        if (size.n < 0)
          LOG(ERROR, call.loc, err_)
              << "Builtin strncmp requires a non-negative size";
      }
    }
    call.type = CreateUInt64();
  }
  else if (call.func == "override")
  {
    if (!bpftrace_.feature_->has_helper_override_return())
    {
      LOG(ERROR, call.loc, err_)
          << "BPF_FUNC_override_return not available for your kernel version";
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
        LOG(ERROR, call.loc, err_)
            << call.func << " can only be used with kprobes.";
      }
    }
  }
  else if (call.func == "kptr" || call.func == "uptr")
  {
    if (!check_nargs(call, 1))
      return;

    // kptr should accept both integer or pointer. Consider case: kptr($1)
    auto &arg = *call.vargs->at(0);
    if (arg.type.type != Type::integer && arg.type.type != Type::pointer)
    {
      LOG(ERROR, call.loc, err_)
          << call.func << "() only supports "
          << "integer or pointer arguments (" << arg.type.type << " provided)";
      return;
    }

    auto as = (call.func == "kptr" ? AddrSpace::kernel : AddrSpace::user);
    call.type = call.vargs->front()->type;
    call.type.SetAS(as);
  }
  else if (call.func == "macaddr")
  {
    if (!check_nargs(call, 1))
      return;

    auto &arg = call.vargs->at(0);

    if (!arg->type.IsIntTy() && !arg->type.IsArrayTy() &&
        !arg->type.IsByteArray() && !arg->type.IsPtrTy())
      LOG(ERROR, call.loc, err_)
          << call.func << "() only supports array or pointer arguments"
          << " (" << arg->type.type << " provided)";

    auto type = arg->type;
    if ((type.IsArrayTy() || type.IsByteArray()) && type.GetSize() != 6)
      LOG(ERROR, call.loc, err_)
          << call.func << "() argument must be 6 bytes in size";

    call.type = CreateMacAddress();
  }
  else if (call.func == "unwatch")
  {
    if (check_nargs(call, 1))
      check_arg(call, Type::integer, 0);

    // Return type cannot be used
    call.type = SizedType(Type::none, 0);
  }
  else
  {
    LOG(ERROR, call.loc, err_) << "Unknown function: '" << call.func << "'";
    call.type = CreateNone();
  }
}

void SemanticAnalyser::check_stack_call(Call &call, bool kernel)
{
  call.type = CreateStack(kernel);
  if (!check_varargs(call, 0, 2))
  {
    return;
  }

  StackType stack_type;
  if (call.vargs)
  {
    switch (call.vargs->size())
    {
      case 0:
        break;
      case 1:
      {
        auto &arg = *call.vargs->at(0);
        // If we have a single argument it can be either
        // stack-mode or stack-size
        if (arg.type.IsStackModeTy())
        {
          if (check_arg(call, Type::stack_mode, 0, true))
            stack_type.mode =
                static_cast<StackMode &>(arg).type.stack_type.mode;
        }
        else
        {
          if (check_arg(call, Type::integer, 0, true))
            stack_type.limit = static_cast<Integer &>(arg).n;
        }
        break;
      }
      case 2:
      {
        if (check_arg(call, Type::stack_mode, 0, true))
        {
          auto &mode_arg = *call.vargs->at(0);
          stack_type.mode =
              static_cast<StackMode &>(mode_arg).type.stack_type.mode;
        }

        if (check_arg(call, Type::integer, 1, true))
        {
          auto &limit_arg = *call.vargs->at(1);
          stack_type.limit = static_cast<Integer &>(limit_arg).n;
        }
        break;
      }
      default:
        LOG(ERROR, call.loc, err_) << "Invalid number of arguments";
        break;
    }
  }
  if (stack_type.limit > MAX_STACK_SIZE)
  {
    LOG(ERROR, call.loc, err_)
        << call.func << "([int limit]): limit shouldn't exceed "
        << MAX_STACK_SIZE << ", " << stack_type.limit << " given";
  }
  call.type = CreateStack(kernel, stack_type);
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
      if (expr->type.IsIntTy() && expr->type.GetSize() < 8)
      {
        std::string type = expr->type.IsSigned() ? "int64" : "uint64";
        Expression *cast = new ast::Cast(type, false, false, expr, map.loc);
        cast->accept(*this);
        map.vargs->at(i) = cast;
        expr = cast;
      }
      else if (expr->type.IsCtxAccess())
      {
        // map functions only accepts a pointer to a element in the stack
        LOG(ERROR, map.loc, err_) << "context cannot be used as a map key";
      }
      else if (expr->type.type == Type::tuple)
      {
        LOG(ERROR, map.loc, err_)
            << "tuple cannot be used as a map key. Try a multi-key associative"
               " array instead (eg `@map[$1, $2] = ...)`.";
      }

      if (is_final_pass()) {
        if (expr->type.IsNoneTy())
          LOG(ERROR, expr->loc, err_) << "Invalid expression for assignment: ";

        SizedType keytype = expr->type;
        // Skip.IsSigned() when comparing keys to not break existing scripts
        // which use maps as a lookup table
        // TODO (fbs): This needs a better solution
        if (expr->type.IsIntTy())
          keytype = CreateUInt(keytype.GetSize() * 8);
        key.args_.push_back(keytype);
      }
    }
  }

  if (is_final_pass()) {
    if (!map.skip_key_validation) {
      auto search = map_key_.find(map.ident);
      if (search != map_key_.end()) {
        if (search->second != key) {
          LOG(ERROR, map.loc, err_)
              << "Argument mismatch for " << map.ident << ": "
              << "trying to access with arguments: " << key.argument_type_list()
              << " when map expects arguments: "
              << search->second.argument_type_list();
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
      LOG(ERROR, map.loc, err_) << "Undefined map: " << map.ident;
    }
    map.type = CreateNone();
  }

  // MapKey default initializes to no args so we don't need to do anything
  // if we don't find a key here
  auto map_key_search_val = map_key_.find(map.ident);
  if (map_key_search_val != map_key_.end())
    map.key_type = map_key_search_val->second;
}

void SemanticAnalyser::visit(Variable &var)
{
  auto search_val = variable_val_.find(var.ident);
  if (search_val != variable_val_.end()) {
    var.type = search_val->second;
  }
  else {
    LOG(ERROR, var.loc, err_)
        << "Undefined or undeclared variable: " << var.ident;
    var.type = CreateNone();
  }
}

void SemanticAnalyser::visit(ArrayAccess &arr)
{
  arr.expr->accept(*this);
  arr.indexpr->accept(*this);

  SizedType &type = arr.expr->type;
  SizedType &indextype = arr.indexpr->type;

  if (is_final_pass()) {
    if (!type.IsArrayTy() && !type.IsPtrTy())
    {
      LOG(ERROR, arr.loc, err_) << "The array index operator [] can only be "
                                   "used on arrays and pointers, found "
                                << type.type << ".";
      return;
    }

    if (type.IsPtrTy() && type.GetPointeeTy()->GetSize() == 0)
    {
      LOG(ERROR, arr.loc, err_) << "The array index operator [] cannot be used "
                                   "on a pointer to an unsized type (void *).";
    }

    if (indextype.IsIntTy() && arr.indexpr->is_literal)
    {
      if (type.IsArrayTy())
      {
        Integer *index = static_cast<Integer *>(arr.indexpr);

        if ((size_t)index->n >= type.GetNumElements())
          LOG(ERROR, arr.loc, err_) << "the index " << index->n
                                    << " is out of bounds for array of size "
                                    << type.GetNumElements();
      }
    }
    else {
      LOG(ERROR, arr.loc, err_) << "The array index operator [] only "
                                   "accepts literal integer indices.";
    }
  }

  if (type.IsArrayTy())
    arr.type = *type.GetElementTy();
  else if (type.IsPtrTy())
    arr.type = *type.GetPointeeTy();
  else
    arr.type = CreateNone();
  arr.type.is_internal = type.is_internal;
  arr.type.SetAS(type.GetAS());
}

void SemanticAnalyser::binop_int(Binop &binop)
{
  auto get_int_literal = [](const auto expr) -> long {
    return static_cast<ast::Integer *>(expr)->n;
  };

  bool lsign = binop.left->type.IsSigned();
  bool rsign = binop.right->type.IsSigned();

  auto left = binop.left;
  auto right = binop.right;

  // First check if operand signedness is the same
  if (lsign != rsign)
  {
    // Convert operands to unsigned if it helps make (lsign == rsign)
    //
    // For example:
    //
    // unsigned int a;
    // if (a > 10) ...;
    //
    // No warning should be emitted as we know that 10 can be
    // represented as unsigned int
    if (lsign && !rsign && left->is_literal && get_int_literal(left) >= 0)
    {
      lsign = false;
    }
    // The reverse (10 < a) should also hold
    else if (!lsign && rsign && right->is_literal &&
             get_int_literal(right) >= 0)
    {
      rsign = false;
    }
    else
    {
      switch (binop.op)
      {
        case bpftrace::Parser::token::EQ:
        case bpftrace::Parser::token::NE:
        case bpftrace::Parser::token::LE:
        case bpftrace::Parser::token::GE:
        case bpftrace::Parser::token::LT:
        case bpftrace::Parser::token::GT:
          LOG(WARNING, binop.loc, out_)
              << "comparison of integers of different signs: '" << left->type
              << "' and '" << right->type << "'"
              << " can lead to undefined behavior";
          break;
        case bpftrace::Parser::token::PLUS:
        case bpftrace::Parser::token::MINUS:
        case bpftrace::Parser::token::MUL:
        case bpftrace::Parser::token::DIV:
        case bpftrace::Parser::token::MOD:
          LOG(WARNING, binop.loc, out_)
              << "arithmetic on integers of different signs: '" << left->type
              << "' and '" << right->type << "'"
              << " can lead to undefined behavior";
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
      binop.op == bpftrace::Parser::token::MOD)
  {
    // Convert operands to unsigned if possible
    if (lsign && left->is_literal && get_int_literal(left) >= 0)
      lsign = false;
    if (rsign && right->is_literal && get_int_literal(right) >= 0)
      rsign = false;

    // If they're still signed, we have to warn
    if (lsign || rsign)
    {
      LOG(WARNING, binop.loc, out_) << "signed operands for '" << opstr(binop)
                                    << "' can lead to undefined behavior "
                                    << "(cast to unsigned to silence warning)";
    }
  }

  if (func_ == "str")
  {
    // Check if one of the operands is a positional parameter
    // The other one should be a constant offset
    auto pos_param = dynamic_cast<PositionalParameter *>(left);
    auto offset = dynamic_cast<Integer *>(right);
    if (!pos_param)
    {
      pos_param = dynamic_cast<PositionalParameter *>(right);
      offset = dynamic_cast<Integer *>(left);
    }

    if (pos_param)
    {
      auto len = bpftrace_.get_param(pos_param->n, true).length();
      if (!offset || binop.op != bpftrace::Parser::token::PLUS ||
          offset->n < 0 || (size_t)offset->n > len)
      {
        LOG(ERROR, binop.loc + binop.right->loc, err_)
            << "only addition of a single constant less or equal to the "
            << "length of $" << pos_param->n << " (which is " << len << ")"
            << " is allowed inside str()";
      }
    }
  }
}

void SemanticAnalyser::visit(Binop &binop)
{
  binop.left->accept(*this);
  binop.right->accept(*this);

  auto &lht = binop.left->type;
  auto &rht = binop.right->type;
  bool lsign = binop.left->type.IsSigned();
  bool rsign = binop.right->type.IsSigned();

  bool is_signed = lsign && rsign;
  switch (binop.op) {
    case bpftrace::Parser::token::LEFT:
    case bpftrace::Parser::token::RIGHT:
      is_signed = lsign;
      break;
    default:
      break;
  }

  binop.type = CreateInteger(64, is_signed);

  auto addr_lhs = binop.left->type.GetAS();
  auto addr_rhs = binop.right->type.GetAS();

  // if lhs or rhs has different addrspace (not none), then set the
  // addrspace to none. This preserves the behaviour for x86.
  if (addr_lhs != addr_rhs && addr_lhs != AddrSpace::none &&
      addr_rhs != AddrSpace::none)
  {
    if (is_final_pass())
      LOG(WARNING, binop.loc, out_) << "Addrspace mismatch";
    binop.type.SetAS(AddrSpace::none);
  }
  // Associativity from left to right for binary operator
  else if (addr_lhs != AddrSpace::none)
  {
    binop.type.SetAS(addr_lhs);
  }
  else
  {
    // In case rhs is none, then this triggers warning in selectProbeReadHelper.
    binop.type.SetAS(addr_rhs);
  }

  if (!is_final_pass())
  {
    return;
  }

  if (lht.IsIntTy() && rht.IsIntTy())
  {
    binop_int(binop);
  }
  else if ((lht.IsPtrTy() && rht.IsIntTy()) || (lht.IsIntTy() && rht.IsPtrTy()))
  {
    // noop
  }
  // Compare type here, not the sized type as we it needs to work on strings of
  // different lengths
  else if (lht.type != rht.type)
  {
    LOG(ERROR, binop.left->loc + binop.right->loc, err_)
        << "Type mismatch for '" << opstr(binop) << "': comparing '" << lht
        << "' with '" << rht << "'";
  }
  // Also allow combination like reg("sp") + 8
  else if (binop.op != Parser::token::EQ && binop.op != Parser::token::NE)
  {
    LOG(ERROR, binop.loc, err_)
        << "The " << opstr(binop)
        << " operator can not be used on expressions of types " << lht << ", "
        << rht;
  }
  else if (binop.op == Parser::token::EQ &&
           ((!binop.left->is_literal && binop.right->is_literal) ||
            (binop.left->is_literal && !binop.right->is_literal)))
  {
    auto *lit = binop.left->is_literal ? binop.left : binop.right;
    auto *str = lit == binop.left ? binop.right : binop.left;
    auto lit_len = bpftrace_.get_string_literal(lit).size();
    auto str_len = str->type.GetNumElements();
    if (lit_len > str_len)
    {
      LOG(WARNING, binop.left->loc + binop.loc + binop.right->loc, out_)
          << "The literal is longer than the variable string (size=" << str_len
          << "), condition will always be false";
    }
  }
}

void SemanticAnalyser::visit(Unop &unop)
{
  if (unop.op == Parser::token::INCREMENT ||
      unop.op == Parser::token::DECREMENT) {
    // Handle ++ and -- before visiting unop.expr, because these
    // operators should be able to work with undefined maps.
    if (!unop.expr->is_map && !unop.expr->is_variable) {
      LOG(ERROR, unop.loc, err_)
          << "The " << opstr(unop)
          << " operator must be applied to a map or variable";
    }
    if (unop.expr->is_map) {
      Map &map = static_cast<Map&>(*unop.expr);
      assign_map_type(map, CreateInt64());
    }
  }

  unop.expr->accept(*this);

  SizedType &type = unop.expr->type;
  if (is_final_pass())
  {
    // Unops are only allowed on ints (e.g. ~$x), dereference only on pointers
    if (!type.IsIntegerTy() &&
        !(unop.op == Parser::token::MUL && type.IsPtrTy()))
    {
      LOG(ERROR, unop.loc, err_)
          << "The " << opstr(unop)
          << " operator can not be used on expressions of type '" << type
          << "'";
    }
  }

  if (unop.op == Parser::token::MUL)
  {
    if (type.IsPtrTy())
    {
      unop.type = SizedType(*type.GetPointeeTy());
      if (type.IsCtxAccess())
      {
        unop.type.MarkCtxAccess();
        unop.type.is_kfarg = type.is_kfarg;
        unop.type.is_tparg = type.is_tparg;
      }
      unop.type.SetAS(type.GetAS());
    }
    else if (type.IsRecordTy())
    {
      LOG(ERROR, unop.loc, err_) << "Can not dereference struct/union of type '"
                                 << type.GetName() << "'. It is not a pointer.";
    }
    else if (type.IsIntTy())
    {
      unop.type = CreateUInt64();
    }
  }
  else if (unop.op == Parser::token::LNOT) {
    // CreateUInt() abort if a size is invalid, so check the size here
    if (!(type.GetSize() == 0 || type.GetSize() == 1 || type.GetSize() == 2 ||
          type.GetSize() == 4 || type.GetSize() == 8))
    {
      LOG(ERROR, unop.loc, err_)
          << "The " << opstr(unop)
          << " operator can not be used on expressions of type '" << type
          << "'";
    }
    else
    {
      unop.type = CreateUInt(8 * type.GetSize());
    }
  }
  else {
    unop.type = CreateInteger(64, type.IsSigned());
  }
}

void SemanticAnalyser::visit(Ternary &ternary)
{
  ternary.cond->accept(*this);
  ternary.left->accept(*this);
  ternary.right->accept(*this);
  Type &cond = ternary.cond->type.type;
  Type &lhs = ternary.left->type.type;
  Type &rhs = ternary.right->type.type;
  if (is_final_pass()) {
    if (lhs != rhs) {
      LOG(ERROR, ternary.loc, err_)
          << "Ternary operator must return the same type: "
          << "have '" << lhs << "' and '" << rhs << "'";
    }
    if (cond != Type::integer)
      LOG(ERROR, ternary.loc, err_) << "Invalid condition in ternary: " << cond;
  }
  if (lhs == Type::string)
    ternary.type = CreateString(STRING_SIZE);
  else if (lhs == Type::integer)
    ternary.type = CreateInteger(64, ternary.left->type.IsSigned());
  else if (lhs == Type::none)
    ternary.type = CreateNone();
  else {
    LOG(ERROR, ternary.loc, err_) << "Ternary return type unsupported " << lhs;
  }
}

void SemanticAnalyser::visit(If &if_block)
{
  if_block.cond->accept(*this);

  if (is_final_pass())
  {
    Type &cond = if_block.cond->type.type;
    if (cond != Type::integer)
      LOG(ERROR, if_block.loc, err_) << "Invalid condition in if(): " << cond;
  }

  accept_statements(if_block.stmts);

  if (if_block.else_stmts)
    accept_statements(if_block.else_stmts);
}

void SemanticAnalyser::visit(Unroll &unroll)
{
  unroll.expr->accept(*this);

  unroll.var = 0;

  if (auto *integer = dynamic_cast<Integer *>(unroll.expr))
  {
    unroll.var = integer->n;
  }
  else if (auto *param = dynamic_cast<PositionalParameter *>(unroll.expr))
  {
    if (param->ptype == PositionalParameterType::count)
    {
      unroll.var = bpftrace_.num_params();
    }
    else
    {
      std::string pstr = bpftrace_.get_param(param->n, param->is_in_str);
      if (is_numeric(pstr))
        unroll.var = std::stoll(pstr, nullptr, 0);
      else
        LOG(ERROR, unroll.loc, err_) << "Invalid positonal params: " << pstr;
    }
  }
  else
  {
    out_ << "Unsupported expression" << std::endl;
    abort();
  }

  if (unroll.var > 100)
  {
    LOG(ERROR, unroll.loc, err_) << "unroll maximum value is 100";
  }
  else if (unroll.var < 1)
  {
    LOG(ERROR, unroll.loc, err_) << "unroll minimum value is 1";
  }

  for (int i = 0; i < unroll.var; i++)
    accept_statements(unroll.stmts);
}

void SemanticAnalyser::visit(Jump &jump)
{
  switch (jump.ident)
  {
    case bpftrace::Parser::token::RETURN:
      // return can be used outside of loops
      break;
    case bpftrace::Parser::token::BREAK:
    case bpftrace::Parser::token::CONTINUE:
      if (!in_loop())
        LOG(ERROR, jump.loc, err_) << opstr(jump) << " used outside of a loop";
      break;
    default:
      LOG(ERROR, jump.loc, err_) << "Unknown jump: '" << opstr(jump) << "'";
  }
}

void SemanticAnalyser::visit(While &while_block)
{
  if (is_final_pass() && !bpftrace_.feature_->has_loop())
  {
    LOG(WARNING, while_block.loc, out_)
        << "Kernel does not support bounded loops. Depending"
           " on LLVMs loop unroll to generate loadable code.";
  }

  while_block.cond->accept(*this);

  loop_depth_++;
  accept_statements(while_block.stmts);
  loop_depth_--;
}

void SemanticAnalyser::visit(FieldAccess &acc)
{
  // A field access must have a field XOR index
  assert((acc.field.size() > 0) != (acc.index >= 0));

  acc.expr->accept(*this);

  SizedType &type = acc.expr->type;

  if (type.IsPtrTy())
  {
    LOG(ERROR, acc.loc, err_)
        << "Can not access field '" << acc.field << "' on type '" << type
        << "'. Try dereferencing it first, or using '->'";
    return;
  }

  if (!type.IsRecordTy() && !type.IsTupleTy())
  {
    if (is_final_pass())
    {
      std::string field;
      if (acc.field.size())
        field += "field '" + acc.field + "'";
      else
        field += "index " + std::to_string(acc.index);

      LOG(ERROR, acc.loc, err_) << "Can not access " << field
                                << " on expression of type '" << type << "'";
    }
    return;
  }

  if (type.is_kfarg)
  {
    auto it = ap_args_.find(acc.field);

    if (it != ap_args_.end())
    {
      acc.type = it->second;
      acc.type.SetAS(acc.expr->type.GetAS());
    }
    else
    {
      LOG(ERROR, acc.loc, err_) << "Can't find a field " << acc.field;
    }
    return;
  }

  if (type.IsTupleTy())
  {
    if (acc.index < 0)
    {
      LOG(ERROR, acc.loc, err_)
          << "Tuples must be indexed with a constant and non-negative integer";
      return;
    }

    bool valid_idx = static_cast<size_t>(acc.index) < type.GetFields().size();

    // We may not have inferred the full type of the tuple yet in early passes
    // so wait until the final pass.
    if (!valid_idx && is_final_pass())
      LOG(ERROR, acc.loc, err_)
          << "Invalid tuple index: " << acc.index << ". Found "
          << type.GetFields().size() << " elements in tuple.";

    if (valid_idx)
      acc.type = type.GetField(acc.index).type;

    return;
  }

  if (!bpftrace_.structs.Has(type.GetName()))
  {
    LOG(ERROR, acc.loc, err_)
        << "Unknown struct/union: '" << type.GetName() << "'";
    return;
  }

  std::map<std::string, std::weak_ptr<const Struct>> structs;

  if (type.is_tparg)
  {
    for (AttachPoint *attach_point : *probe_->attach_points)
    {
      if (probetype(attach_point->provider) != ProbeType::tracepoint)
      {
        // The args builtin can only be used with tracepoint
        // an error message is already generated in visit(Builtin)
        // just continue semantic analysis
        continue;
      }

      auto matches = bpftrace_.probe_matcher_->get_matches_for_ap(
          *attach_point);
      for (auto &match : matches) {
        std::string tracepoint_struct = TracepointFormatParser::get_struct_name(
            match);
        structs[tracepoint_struct] = bpftrace_.structs.Lookup(
            tracepoint_struct);
      }
    }
  }
  else
  {
    structs[type.GetName()] = type.GetStruct();
  }

  for (auto it : structs) {
    std::string cast_type = it.first;
    const auto record = it.second.lock();
    if (!record->HasField(acc.field))
    {
      LOG(ERROR, acc.loc, err_)
          << "Struct/union of type '" << cast_type << "' does not contain "
          << "a field named '" << acc.field << "'";
    }
    else {
      const auto &field = record->GetField(acc.field);

      acc.type = field.type;
      if (acc.expr->type.IsCtxAccess() &&
          (acc.type.IsArrayTy() || acc.type.IsRecordTy()))
      {
        // e.g., ((struct bpf_perf_event_data*)ctx)->regs.ax
        acc.type.MarkCtxAccess();
      }
      acc.type.is_internal = type.is_internal;
      acc.type.SetAS(acc.expr->type.GetAS());

      // The kernel uses the first 8 bytes to store `struct pt_regs`. Any
      // access to the first 8 bytes results in verifier error.
      if (type.is_tparg && field.offset < 8)
        LOG(ERROR, acc.loc, err_)
            << "BPF does not support accessing common tracepoint fields";
    }
  }
}

void SemanticAnalyser::visit(Cast &cast)
{
  cast.expr->accept(*this);

  if (cast.expr->type.IsRecordTy())
  {
    LOG(ERROR, cast.loc, err_)
        << "Cannot cast from struct type \"" << cast.expr->type << "\"";
  }

  bool is_ctx = cast.expr->type.IsCtxAccess();
  auto &intcasts = getIntcasts();
  auto k_v = intcasts.find(cast.cast_type);

  // Built-in int types
  if (k_v != intcasts.end())
  {
    auto &v = k_v->second;
    if (cast.is_pointer)
    {
      cast.type = CreatePointer(CreateInteger(std::get<0>(v), std::get<1>(v)));
      if (is_ctx)
      {
        LOG(ERROR, cast.loc, err_)
            << "Integer pointer casts are not supported for type: ctx";
      }

      if (cast.is_double_pointer)
        cast.type = CreatePointer(cast.type);
    }
    else
    {
      cast.type = CreateInteger(std::get<0>(v), std::get<1>(v));

      auto rhs = cast.expr->type;
      // Casting Type::ctx to Type::integer is supported to access a
      // tracepoint's __data_loc field. See #990 and #770
      // In this case, the context information will be lost
      if (!rhs.IsIntTy() && !rhs.IsRecordTy() && !rhs.IsPtrTy() &&
          !rhs.IsCtxAccess())
      {
        LOG(ERROR, cast.loc, err_)
            << "Casts are not supported for type: \"" << rhs << "\"";
      }
    }
    // Consider both case *(int8)(retval) and *(int8*)retval
    cast.type.SetAS(cast.expr->type.GetAS());
    return;
  }

  if (!bpftrace_.structs.Has(cast.cast_type))
  {
    LOG(ERROR, cast.loc, err_)
        << "Unknown struct/union: '" << cast.cast_type << "'";
    return;
  }

  SizedType struct_type = CreateRecord(
      cast.cast_type, bpftrace_.structs.Lookup(cast.cast_type));

  if (cast.is_pointer)
  {
    cast.type = CreatePointer(struct_type);

    if (cast.is_double_pointer)
      cast.type = CreatePointer(cast.type);
  }
  else
  {
    LOG(ERROR, cast.loc, err_)
        << "Cannot cast to struct type \"" << cast.cast_type << "\"";
  }
  if (is_ctx)
    cast.type.MarkCtxAccess();

  cast.type.SetAS(cast.expr->type.GetAS());
  // case : BEGIN { @foo = (struct Foo)0; }
  // case : profile:hz:99 $task = (struct task_struct *)curtask.
  if (cast.type.GetAS() == AddrSpace::none)
  {
    ProbeType type = single_provider_type();
    cast.type.SetAS(find_addrspace(type));
  }
}

void SemanticAnalyser::visit(Tuple &tuple)
{
  std::vector<SizedType> elements;
  for (size_t i = 0; i < tuple.elems->size(); ++i)
  {
    Expression *elem = tuple.elems->at(i);
    elem->accept(*this);

    // If elem type is none that means that the tuple contains some
    // invalid cast (e.g., (0, (aaa)0)). In this case, skip the tuple
    // creation. Cast already emits the error.
    if (elem->type.IsNoneTy() || elem->type.GetSize() == 0)
      return;
    elements.emplace_back(elem->type);
  }

  tuple.type = CreateTuple(bpftrace_.structs.AddTuple(elements));
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
  auto type = assignment.expr->type;

  if (type.IsRecordTy())
  {
    std::string ty = assignment.expr->type.GetName();
    std::string stored_ty = map_val_[map_ident].GetName();
    if (!stored_ty.empty() && stored_ty != ty)
    {
      LOG(ERROR, assignment.loc, err_)
          << "Type mismatch for " << map_ident << ": "
          << "trying to assign value of type '" << ty
          << "' when map already contains a value of type '" << stored_ty
          << "''";
    }
    else
    {
      map_val_[map_ident] = assignment.expr->type;
      map_val_[map_ident].is_internal = true;
    }
  }
  else if (type.IsStringTy())
  {
    auto map_size = map_val_[map_ident].GetSize();
    auto expr_size = assignment.expr->type.GetSize();
    if (map_size != expr_size)
    {
      std::stringstream buf;
      buf << "String size mismatch: " << map_size << " != " << expr_size << ".";
      if (map_size < expr_size)
      {
        buf << " The value may be truncated.";
        LOG(WARNING, assignment.loc, out_) << buf.str();
      }
      else
      {
        // bpf_map_update_elem() expects map_size-length value
        LOG(ERROR, assignment.loc, err_) << buf.str();
      }
    }
  }
  else if (type.IsBufferTy())
  {
    auto map_size = map_val_[map_ident].GetSize();
    auto expr_size = assignment.expr->type.GetSize();
    if (map_size != expr_size)
    {
      std::stringstream buf;
      buf << "Buffer size mismatch: " << map_size << " != " << expr_size << ".";
      if (map_size < expr_size)
      {
        buf << " The value may be truncated.";
        LOG(WARNING, assignment.loc, out_) << buf.str();
      }
      else
      {
        // bpf_map_update_elem() expects map_size-length value
        LOG(ERROR, assignment.loc, err_) << buf.str();
      }
    }
  }
  else if (type.IsCtxAccess())
  {
    // bpf_map_update_elem() only accepts a pointer to a element in the stack
    LOG(ERROR, assignment.loc, err_) << "context cannot be assigned to a map";
  }
  else if (type.IsTupleTy())
  {
    // Early passes may not have been able to deduce the full types of tuple
    // elements yet. So wait until final pass.
    if (is_final_pass())
    {
      const auto &map_type = map_val_[map_ident];
      const auto &expr_type = assignment.expr->type;
      if (map_type != expr_type)
      {
        LOG(ERROR, assignment.loc, err_) << "Tuple type mismatch: " << map_type
                                         << " != " << expr_type << ".";
      }
    }
  }
  else if (type.IsArrayTy())
  {
    const auto &map_type = map_val_[map_ident];
    const auto &expr_type = assignment.expr->type;
    if (map_type == expr_type)
    {
      map_val_[map_ident].is_internal = true;
    }
  }

  if (is_final_pass())
  {
    if (type.IsNoneTy())
      LOG(ERROR, assignment.expr->loc, err_)
          << "Invalid expression for assignment: " << type;
  }
}

void SemanticAnalyser::visit(AssignVarStatement &assignment)
{
  assignment.expr->accept(*this);

  std::string var_ident = assignment.var->ident;
  auto search = variable_val_.find(var_ident);
  assignment.var->type = assignment.expr->type;

  auto *builtin = dynamic_cast<Builtin *>(assignment.expr);
  if (builtin && builtin->ident == "args" && builtin->type.is_kfarg)
  {
    LOG(ERROR, assignment.loc, err_) << "args cannot be assigned to a variable";
  }

  if (search != variable_val_.end()) {
    if (search->second.IsNoneTy())
    {
      if (is_final_pass()) {
        LOG(ERROR, assignment.loc, err_) << "Undefined variable: " + var_ident;
      }
      else {
        search->second = assignment.expr->type;
      }
    }
    else if (!search->second.IsSameType(assignment.expr->type))
    {
      LOG(ERROR, assignment.loc, err_)
          << "Type mismatch for " << var_ident << ": "
          << "trying to assign value of type '" << assignment.expr->type
          << "' when variable already contains a value of type '"
          << search->second << "'";
    }
  }
  else {
    // This variable hasn't been seen before
    variable_val_[var_ident] = assignment.expr->type;
    assignment.var->type = assignment.expr->type;
  }

  auto &storedTy = variable_val_[var_ident];
  auto &assignTy = assignment.expr->type;

  if (assignTy.IsRecordTy())
  {
    if (assignTy.GetName() != storedTy.GetName())
    {
      LOG(ERROR, assignment.loc, err_)
          << "Type mismatch for " << var_ident << ": "
          << "trying to assign value of type '" << assignTy.GetName()
          << "' when variable already contains a value of type '" << storedTy;
    }
  }
  else if (assignTy.IsStringTy())
  {
    auto var_size = storedTy.GetSize();
    auto expr_size = assignTy.GetSize();
    if (var_size != expr_size)
    {
      LOG(WARNING, assignment.loc, out_)
          << "String size mismatch: " << var_size << " != " << expr_size
          << (var_size < expr_size ? ". The value may be truncated."
                                   : ". The value may contain garbage.");
    }
  }
  else if (assignTy.IsBufferTy())
  {
    auto var_size = storedTy.GetSize();
    auto expr_size = assignTy.GetSize();
    if (var_size != expr_size)
    {
      LOG(WARNING, assignment.loc, out_)
          << "Buffer size mismatch: " << var_size << " != " << expr_size
          << (var_size < expr_size ? ". The value may be truncated."
                                   : ". The value may contain garbage.");
    }
  }
  else if (assignTy.IsTupleTy())
  {
    // Early passes may not have been able to deduce the full types of tuple
    // elements yet. So wait until final pass.
    if (is_final_pass())
    {
      auto var_type = storedTy;
      auto expr_type = assignTy;
      if (var_type != expr_type)
      {
        LOG(ERROR, assignment.loc, err_) << "Tuple type mismatch: " << var_type
                                         << " != " << expr_type << ".";
      }
    }
  }

  if (is_final_pass())
  {
    auto &ty = assignTy.type;
    if (ty == Type::none)
      LOG(ERROR, assignment.expr->loc, err_)
          << "Invalid expression for assignment: " << ty;
  }
}

void SemanticAnalyser::visit(Predicate &pred)
{
  pred.expr->accept(*this);
  if (is_final_pass())
  {
    SizedType &ty = pred.expr->type;
    if (!ty.IsIntTy() && !ty.IsPtrTy())
    {
      LOG(ERROR, pred.loc, err_)
          << "Invalid type for predicate: " << pred.expr->type.type;
    }
  }
}

void SemanticAnalyser::visit(AttachPoint &ap)
{
  ap.provider = probetypeName(ap.provider);

  if (ap.provider == "kprobe" || ap.provider == "kretprobe") {
    if (ap.target != "")
      LOG(ERROR, ap.loc, err_) << "kprobes should not have a target";
    if (ap.func == "")
      LOG(ERROR, ap.loc, err_) << "kprobes should be attached to a function";
    if (is_final_pass())
    {
      // Warn if user tries to attach to a non-traceable function
      if (!has_wildcard(ap.func) && !bpftrace_.is_traceable_func(ap.func))
      {
        LOG(WARNING, ap.loc, out_)
            << ap.func
            << " is not traceable (probably it is inlined or marked as "
               "\"notrace\"), attaching to it will likely fail";
      }
    }
  }
  else if (ap.provider == "uprobe" || ap.provider == "uretprobe") {
    if (ap.target == "")
      LOG(ERROR, ap.loc, err_) << ap.provider << " should have a target";
    if (ap.func == "" && ap.address == 0)
      LOG(ERROR, ap.loc, err_)
          << ap.provider << " should be attached to a function and/or address";

    if (ap.provider == "uretprobe" && ap.func_offset != 0)
      LOG(ERROR, ap.loc, err_)
          << "uretprobes can not be attached to a function offset";

    auto paths = resolve_binary_path(ap.target, bpftrace_.pid());
    switch (paths.size())
    {
    case 0:
      LOG(ERROR, ap.loc, err_) << "uprobe target file '" << ap.target
                               << "' does not exist or is not executable";
      break;
    case 1:
      ap.target = paths.front();
      break;
    default:
      // If we are doing a PATH lookup (ie not glob), we follow shell
      // behavior and take the first match.
      // Otherwise we keep the target with glob, it will be expanded later
      if (ap.target.find("*") == std::string::npos)
      {
        LOG(WARNING, ap.loc, out_)
            << "attaching to uprobe target file '" << paths.front()
            << "' but matched " << std::to_string(paths.size()) << " binaries";
        ap.target = paths.front();
      }
    }
  }
  else if (ap.provider == "usdt") {
    bpftrace_.has_usdt_ = true;
    if (ap.func == "")
      LOG(ERROR, ap.loc, err_)
          << "usdt probe must have a target function or wildcard";

    if (ap.target != "" && !(bpftrace_.pid() > 0 && has_wildcard(ap.target)))
    {
      auto paths = resolve_binary_path(ap.target, bpftrace_.pid());
      switch (paths.size())
      {
      case 0:
        LOG(ERROR, ap.loc, err_) << "usdt target file '" << ap.target
                                 << "' does not exist or is not executable";
        break;
      case 1:
        ap.target = paths.front();
        break;
      default:
        // If we are doing a PATH lookup (ie not glob), we follow shell
        // behavior and take the first match.
        // Otherwise we keep the target with glob, it will be expanded later
        if (ap.target.find("*") == std::string::npos)
        {
          LOG(WARNING, ap.loc, out_)
              << "attaching to usdt target file '" << paths.front()
              << "' but matched " << std::to_string(paths.size())
              << " binaries";
          ap.target = paths.front();
        }
      }
    }

    if (bpftrace_.pid() > 0)
    {
      USDTHelper::probes_for_pid(bpftrace_.pid());
    }
    else if (ap.target != "")
    {
      for (auto &path : resolve_binary_path(ap.target))
        USDTHelper::probes_for_path(path);
    }
    else
    {
      LOG(ERROR, ap.loc, err_)
          << "usdt probe must specify at least path or pid to probe";
    }
  }
  else if (ap.provider == "tracepoint") {
    if (ap.target == "" || ap.func == "")
      LOG(ERROR, ap.loc, err_) << "tracepoint probe must have a target";
  }
  else if (ap.provider == "profile") {
    if (ap.target == "")
      LOG(ERROR, ap.loc, err_) << "profile probe must have unit of time";
    else if (ap.target != "hz" &&
             ap.target != "us" &&
             ap.target != "ms" &&
             ap.target != "s")
      LOG(ERROR, ap.loc, err_)
          << ap.target << " is not an accepted unit of time";
    if (ap.func != "")
      LOG(ERROR, ap.loc, err_)
          << "profile probe must have an integer frequency";
    else if (ap.freq <= 0)
      LOG(ERROR, ap.loc, err_)
          << "profile frequency should be a positive integer";
  }
  else if (ap.provider == "interval") {
    if (ap.target == "")
      LOG(ERROR, ap.loc, err_) << "interval probe must have unit of time";
    else if (ap.target != "ms" && ap.target != "s" && ap.target != "us" &&
             ap.target != "hz")
      LOG(ERROR, ap.loc, err_)
          << ap.target << " is not an accepted unit of time";
    if (ap.func != "")
      LOG(ERROR, ap.loc, err_)
          << "interval probe must have an integer frequency";
  }
  else if (ap.provider == "software") {
    if (ap.target == "")
      LOG(ERROR, ap.loc, err_)
          << "software probe must have a software event name";
    else {
      if (!has_wildcard(ap.target) && !ap.ignore_invalid)
      {
        bool found = false;
        for (auto &probeListItem : SW_PROBE_LIST)
        {
          if (ap.target == probeListItem.path ||
              (!probeListItem.alias.empty() &&
               ap.target == probeListItem.alias))
          {
            found = true;
            break;
          }
        }
        if (!found)
          LOG(ERROR, ap.loc, err_) << ap.target << " is not a software probe";
      }
      else if (!listing_)
      {
        LOG(ERROR, ap.loc, err_)
            << "wildcards are not allowed for hardware probe type";
      }
    }
    if (ap.func != "")
      LOG(ERROR, ap.loc, err_)
          << "software probe can only have an integer count";
    else if (ap.freq < 0)
      LOG(ERROR, ap.loc, err_) << "software count should be a positive integer";
  }
  else if (ap.provider == "watchpoint" || ap.provider == "asyncwatchpoint")
  {
    if (ap.func.size())
    {
      if (bpftrace_.pid() <= 0 && !has_child_)
        LOG(ERROR, ap.loc, err_) << "-p PID or -c CMD required for watchpoint";

      if (ap.address > static_cast<uint64_t>(arch::max_arg()))
        LOG(ERROR, ap.loc, err_)
            << arch::name() << " doesn't support arg" << ap.address;
    }
    else if (ap.provider == "asyncwatchpoint")
      LOG(ERROR, ap.loc, err_) << ap.provider << " requires a function name";
    else if (!ap.address)
      LOG(ERROR, ap.loc, err_)
          << "watchpoint must be attached to a non-zero address";
    if (ap.len != 1 && ap.len != 2 && ap.len != 4 && ap.len != 8)
      LOG(ERROR, ap.loc, err_) << "watchpoint length must be one of (1,2,4,8)";
    if (ap.mode.empty())
      LOG(ERROR, ap.loc, err_)
          << "watchpoint mode must be combination of (r,w,x)";
    std::sort(ap.mode.begin(), ap.mode.end());
    for (const char c : ap.mode) {
      if (c != 'r' && c != 'w' && c != 'x')
        LOG(ERROR, ap.loc, err_)
            << "watchpoint mode must be combination of (r,w,x)";
    }
    for (size_t i = 1; i < ap.mode.size(); ++i)
    {
      if (ap.mode[i - 1] == ap.mode[i])
        LOG(ERROR, ap.loc, err_) << "watchpoint modes may not be duplicated";
    }
    const auto invalid_modes = arch::invalid_watchpoint_modes();
    if (std::any_of(invalid_modes.cbegin(),
                    invalid_modes.cend(),
                    [&](const auto &mode) { return mode == ap.mode; }))
      LOG(ERROR, ap.loc, err_) << "invalid watchpoint mode: " << ap.mode;
  }
  else if (ap.provider == "hardware") {
    if (ap.target == "")
      LOG(ERROR, ap.loc, err_)
          << "hardware probe must have a hardware event name";
    else {
      if (!has_wildcard(ap.target) && !ap.ignore_invalid)
      {
        bool found = false;
        for (auto &probeListItem : HW_PROBE_LIST)
        {
          if (ap.target == probeListItem.path ||
              (!probeListItem.alias.empty() &&
               ap.target == probeListItem.alias))
          {
            found = true;
            break;
          }
        }
        if (!found)
          LOG(ERROR, ap.loc, err_) << ap.target + " is not a hardware probe";
      }
      else if (!listing_)
      {
        LOG(ERROR, ap.loc, err_)
            << "wildcards are not allowed for hardware probe type";
      }
    }
    if (ap.func != "")
      LOG(ERROR, ap.loc, err_)
          << "hardware probe can only have an integer count";
    else if (ap.freq < 0)
      LOG(ERROR, ap.loc, err_)
          << "hardware frequency should be a positive integer";
  }
  else if (ap.provider == "BEGIN" || ap.provider == "END") {
    if (ap.target != "" || ap.func != "")
      LOG(ERROR, ap.loc, err_) << "BEGIN/END probes should not have a target";
    if (is_final_pass()) {
      if (ap.provider == "BEGIN") {
        if (has_begin_probe_)
          LOG(ERROR, ap.loc, err_) << "More than one BEGIN probe defined";
        has_begin_probe_ = true;
      }
      if (ap.provider == "END") {
        if (has_end_probe_)
          LOG(ERROR, ap.loc, err_) << "More than one END probe defined";
        has_end_probe_ = true;
      }
    }
  }
  else if (ap.provider == "kfunc" || ap.provider == "kretfunc")
  {
#ifndef HAVE_BCC_KFUNC
    LOG(ERROR, ap.loc, err_)
        << "kfunc/kretfunc not available for your linked against bcc version.";
    return;
#endif

    bool supported = bpftrace_.feature_->has_prog_kfunc() &&
                     bpftrace_.btf_.has_data();
    if (!supported)
    {
      LOG(ERROR, ap.loc, err_)
          << "kfunc/kretfunc not available for your kernel version.";
      return;
    }

    if (ap.func == "")
      LOG(ERROR, ap.loc, err_) << "kfunc should specify a function";

    if (!listing_)
    {
      const auto &ap_map = bpftrace_.btf_ap_args_;
      auto it = ap_map.find(probe_->name());

      if (it != ap_map.end())
      {
        auto args = it->second;
        ap_args_.clear();
        ap_args_.insert(args.begin(), args.end());
      }
      else
      {
        LOG(ERROR, ap.loc, err_) << "Failed to resolve kfunc args.";
      }
    }
  }
  else if (ap.provider == "iter")
  {
    bool supported = false;

    if (ap.func == "task")
    {
      supported = bpftrace_.feature_->has_prog_iter_task() &&
                  bpftrace_.btf_.has_data();
    }
    else if (ap.func == "task_file")
    {
      supported = bpftrace_.feature_->has_prog_iter_task_file() &&
                  bpftrace_.btf_.has_data();
    }
    else if (listing_)
    {
      supported = true;
    }

    if (!supported)
    {
      LOG(ERROR, ap.loc, err_)
          << "iter " << ap.func << " not available for your kernel version.";
    }
  }
  else {
    LOG(ERROR, ap.loc, err_) << "Invalid provider: '" << ap.provider << "'";
  }
}

void SemanticAnalyser::visit(Probe &probe)
{
  auto aps = probe.attach_points->size();

  // Clear out map of variable names - variables should be probe-local
  variable_val_.clear();
  probe_ = &probe;

  for (AttachPoint *ap : *probe.attach_points) {
    if (!listing_ && aps > 1 && ap->provider == "iter")
    {
      LOG(ERROR, ap->loc, err_) << "Only single iter attach point is allowed.";
      return;
    }
    ap->accept(*this);
  }
  if (probe.pred) {
    probe.pred->accept(*this);
  }
  if (probe.stmts)
  {
    for (Statement *stmt : *probe.stmts)
    {
      stmt->accept(*this);
    }
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

  int num_passes = listing_ ? 1 : num_passes_;
  for (pass_ = 1; pass_ <= num_passes; pass_++)
  {
    root_->accept(*this);
    errors = err_.str();
    if (!errors.empty()) {
      out_ << errors;
      return pass_;
    }
  }

  return 0;
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
      LOG(ERROR, call.loc, err_) << call.func
                                 << "() should be assigned to a map or a "
                                    "variable, or be used as a map key";
      return false;
    }
  }
  else if (want_map && want_var)
  {
    if (!call.map && !call.var)
    {
      LOG(ERROR, call.loc, err_)
          << call.func << "() should be assigned to a map or a variable";
      return false;
    }
  }
  else if (want_map && want_map_key)
  {
    if (!call.map && !call.key_for_map)
    {
      LOG(ERROR, call.loc, err_)
          << call.func
          << "() should be assigned to a map or be used as a map key";
      return false;
    }
  }
  else if (want_var && want_map_key)
  {
    if (!call.var && !call.key_for_map)
    {
      LOG(ERROR, call.loc, err_)
          << call.func
          << "() should be assigned to a variable or be used as a map key";
      return false;
    }
  }
  else if (want_map)
  {
    if (!call.map)
    {
      LOG(ERROR, call.loc, err_)
          << call.func << "() should be directly assigned to a map";
      return false;
    }
  }
  else if (want_var)
  {
    if (!call.var)
    {
      LOG(ERROR, call.loc, err_)
          << call.func << "() should be assigned to a variable";
      return false;
    }
  }
  else if (want_map_key)
  {
    if (!call.key_for_map)
    {
      LOG(ERROR, call.loc, err_)
          << call.func << "() should be used as a map key";
      return false;
    }
  }
  else
  {
    if (call.map || call.var || call.key_for_map)
    {
      LOG(ERROR, call.loc, err_)
          << call.func
          << "() should not be used in an assignment or as a map key";
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
    LOG(ERROR, call.loc, err_) << err.str();
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
    LOG(ERROR, call.loc, err_) << err.str();
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
    LOG(ERROR, call.loc, err_) << err.str();
    return false;
  }

  return true;
}

bool SemanticAnalyser::check_arg(const Call &call,
                                 Type type,
                                 int arg_num,
                                 bool want_literal,
                                 bool fail)
{
  if (!call.vargs)
    return false;

  auto &arg = *call.vargs->at(arg_num);
  if (want_literal && (!arg.is_literal || arg.type.type != type))
  {
    if (fail)
    {
      LOG(ERROR, call.loc, err_) << call.func << "() expects a " << type
                                 << " literal (" << arg.type.type << " provided)";
      if (type == Type::string)
      {
        // If the call requires a string literal and a positional parameter is
        // given, tell user to use str()
        auto *pos_param = dynamic_cast<PositionalParameter *>(&arg);
        if (pos_param)
          LOG(ERROR) << "Use str($" << pos_param->n << ") to treat $"
                     << pos_param->n << " as a string";
      }
    }
    return false;
  }
  else if (is_final_pass() && arg.type.type != type) {
    if (fail)
    {
      LOG(ERROR, call.loc, err_)
          << call.func << "() only supports " << type << " arguments ("
          << arg.type.type << " provided)";
    }
    return false;
  }
  return true;
}

bool SemanticAnalyser::check_symbol(const Call &call, int arg_num __attribute__((unused)))
{
  if (!call.vargs)
    return false;

  auto arg = bpftrace_.get_string_literal(call.vargs->at(0));

  std::string re = "^[a-zA-Z0-9./_-]+$";
  bool is_valid = std::regex_match(arg, std::regex(re));
  if (!is_valid)
  {
    LOG(ERROR, call.loc, err_)
        << call.func << "() expects a string that is a valid symbol (" << re
        << ") as input (\"" << arg << "\" provided)";
    return false;
  }

  return true;
}

bool SemanticAnalyser::check_available(const Call &call, const AttachPoint &ap)
{
  auto &func = call.func;
  ProbeType type = probetype(ap.provider);

  if (func == "reg")
  {
    switch (type)
    {
      case ProbeType::kprobe:
      case ProbeType::kretprobe:
      case ProbeType::uprobe:
      case ProbeType::uretprobe:
      case ProbeType::usdt:
      case ProbeType::profile:
      case ProbeType::interval:
      case ProbeType::software:
      case ProbeType::hardware:
      case ProbeType::watchpoint:
      case ProbeType::asyncwatchpoint:
        return true;
      case ProbeType::invalid:
      case ProbeType::tracepoint:
      case ProbeType::kfunc:
      case ProbeType::kretfunc:
      case ProbeType::iter:
        return false;
    }
  }
  else if (func == "uaddr")
  {
    switch (type)
    {
      case ProbeType::usdt:
      case ProbeType::uretprobe:
      case ProbeType::uprobe:
        return true;
      case ProbeType::invalid:
      case ProbeType::kprobe:
      case ProbeType::kretprobe:
      case ProbeType::tracepoint:
      case ProbeType::profile:
      case ProbeType::interval:
      case ProbeType::software:
      case ProbeType::hardware:
      case ProbeType::watchpoint:
      case ProbeType::asyncwatchpoint:
      case ProbeType::kfunc:
      case ProbeType::kretfunc:
      case ProbeType::iter:
        return false;
    }
  }
  else if (func == "signal")
  {
    if (ap.provider == "BEGIN" || ap.provider == "END")
      return false;
    switch (type)
    {
      case ProbeType::kprobe:
      case ProbeType::kretprobe:
      case ProbeType::uprobe:
      case ProbeType::uretprobe:
      case ProbeType::usdt:
      case ProbeType::tracepoint:
      case ProbeType::profile:
      case ProbeType::kfunc:
      case ProbeType::kretfunc:
        return true;
      case ProbeType::invalid:
      case ProbeType::interval:
      case ProbeType::software:
      case ProbeType::hardware:
      case ProbeType::watchpoint:
      case ProbeType::asyncwatchpoint:
      case ProbeType::iter:
        return false;
    }
  }

  if (type == ProbeType::invalid)
    return false;

  return true;
}

void SemanticAnalyser::update_assign_map_type(const Map &map,
                                              SizedType &type,
                                              const SizedType &new_type)
{
  const std::string &map_ident = map.ident;
  if ((type.IsTupleTy() && new_type.IsTupleTy() &&
       type.GetFields().size() != new_type.GetFields().size()) ||
      (type.type != new_type.type) ||
      (type.IsRecordTy() && type.GetName() != new_type.GetName()) ||
      (type.IsArrayTy() && type != new_type))
  {
    LOG(ERROR, map.loc, err_)
        << "Type mismatch for " << map_ident << ": "
        << "trying to assign value of type '" << new_type
        << "' when map already contains a value of type '" << type;
    return;
  }

  // all integers are 64bit
  if (type.IsIntTy())
    return;

  if (type.IsTupleTy() && new_type.IsTupleTy())
  {
    auto &fields = type.GetFields();
    auto &new_fields = new_type.GetFields();
    for (size_t i = 0; i < fields.size(); i++)
    {
      update_assign_map_type(map, fields[i].type, new_fields[i].type);
    }
  }

  type = new_type;
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
    if (search->second.IsNoneTy())
    {
      if (is_final_pass()) {
        LOG(ERROR, map.loc, err_) << "Undefined map: " + map_ident;
      }
      else
      {
        search->second = type;
      }
    }
    else if (search->second.type != type.type) {
      LOG(ERROR, map.loc, err_)
          << "Type mismatch for " << map_ident << ": "
          << "trying to assign value of type '" << type
          << "' when map already contains a value of type '" << search->second;
    }
    update_assign_map_type(map, search->second, type);
  }
  else {
    // This map hasn't been seen before
    map_val_.insert({map_ident, type});
    if (map_val_[map_ident].IsIntTy())
    {
      // Store all integer values as 64-bit in maps, so that there will
      // be space for any integer to be assigned to the map later
      map_val_[map_ident].SetSize(8);
    }
  }
}

void SemanticAnalyser::accept_statements(StatementList *stmts)
{
  for (size_t i = 0; i < stmts->size(); i++)
  {
    auto stmt = stmts->at(i);
    stmt->accept(*this);

    if (is_final_pass())
    {
      auto *jump = dynamic_cast<Jump *>(stmt);
      if (jump && i < (stmts->size() - 1))
      {
        LOG(WARNING, jump->loc, out_)
            << "All code after a '" << opstr(*jump) << "' is unreachable.";
      }
    }
  }
}

Pass CreateSemanticPass()
{
  auto fn = [](Node &n, PassContext &ctx) {
    auto semantics = SemanticAnalyser(&n, ctx.b, !ctx.b.cmd_.empty());
    int err = semantics.analyse();
    if (err)
      return PassResult::Error("");
    return PassResult::Success();
  };

  return Pass("Semantic", fn);
};

} // namespace ast
} // namespace bpftrace
