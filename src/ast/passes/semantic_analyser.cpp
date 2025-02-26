#include "semantic_analyser.h"
#include <arpa/inet.h>

#include <algorithm>
#include <cstring>
#include <regex>
#include <string>
#include <sys/stat.h>

#include "arch/arch.h"
#include "ast/ast.h"
#include "ast/async_event_types.h"
#include "ast/signal_bt.h"
#include "collect_nodes.h"
#include "config.h"
#include "log.h"
#include "printf.h"
#include "probe_matcher.h"
#include "tracepoint_format_parser.h"
#include "types.h"
#include "usdt.h"

namespace bpftrace::ast {

static constexpr std::string_view DELETE_ERROR =
    "delete() expects a map for the first argument and a key for the second "
    "argument e.g. `delete(@my_map, 1);`";

static const std::map<std::string, std::tuple<size_t, bool>> &getIntcasts()
{
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

static std::pair<uint64_t, uint64_t> getUIntTypeRange(const SizedType &ty)
{
  assert(ty.IsIntegerTy());
  auto size = ty.GetSize();
  switch (size) {
    case 1:
      return { 0, std::numeric_limits<uint8_t>::max() };
    case 2:
      return { 0, std::numeric_limits<uint16_t>::max() };
    case 4:
      return { 0, std::numeric_limits<uint32_t>::max() };
    case 8:
      return { 0, std::numeric_limits<uint64_t>::max() };
    default:
      LOG(BUG) << "Unrecognized int type size: " << size;
      return { 0, 0 };
  }
}

static std::pair<int64_t, int64_t> getIntTypeRange(const SizedType &ty)
{
  assert(ty.IsIntegerTy());
  auto size = ty.GetSize();
  switch (size) {
    case 1:
      return { std::numeric_limits<int8_t>::min(),
               std::numeric_limits<int8_t>::max() };
    case 2:
      return { std::numeric_limits<int16_t>::min(),
               std::numeric_limits<int16_t>::max() };
    case 4:
      return { std::numeric_limits<int32_t>::min(),
               std::numeric_limits<int32_t>::max() };
    case 8:
      return { std::numeric_limits<int64_t>::min(),
               std::numeric_limits<int64_t>::max() };
    default:
      LOG(BUG) << "Unrecognized int type size: " << size;
      return { 0, 0 };
  }
}

// These are types which aren't valid for scratch variables
// e.g. this is not valid `let $x: sum_t;`
static bool IsValidVarDeclType(const SizedType &ty)
{
  switch (ty.GetTy()) {
    case Type::avg_t:
    case Type::count_t:
    case Type::hist_t:
    case Type::lhist_t:
    case Type::max_t:
    case Type::min_t:
    case Type::stats_t:
    case Type::sum_t:
    case Type::stack_mode:
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
    case Type::record:
    case Type::tuple:
    case Type::cgroup_path_t:
    case Type::strerror_t:
    case Type::none:
    case Type::reference:
    case Type::timestamp_mode:
      return true;
  }
  return false; // unreachable
}

// These are special map aggregation types that cannot be assigned
// to scratch variables or from one map to another e.g. these are both invalid:
// `@a = hist(10); let $b = @a;`
// `@a = count(); @b = @a;`
// However, if the assigned map already contains integers, we implicitly cast
// the aggregation into an integer to retrieve its value, so this is valid:
// `@a = count(); @b = 0; @b = @a`
bool SemanticAnalyser::is_valid_assignment(const Expression *target,
                                           const Expression *expr)
{
  if (expr->is_map) {
    // Prevent assigning multi-output aggregations to another map.
    if (expr->type.IsMultiOutputMapTy())
      return false;
    // Prevent declaring a map copying another aggregate map.
    if (auto *target_map = dynamic_cast<const Map *>(target)) {
      bool map_has_type = get_map_type(*target_map);
      if (expr->type.IsCastableMapTy() && map_has_type == false)
        return false;
    }
  }
  return true;
}

void SemanticAnalyser::visit(Integer &integer)
{
  if (integer.is_negative) {
    integer.type = CreateInt64();
  } else {
    // Default to signed unless the original value is too large
    uint64_t val = static_cast<uint64_t>(integer.n);
    if (val > std::numeric_limits<int32_t>::max()) {
      integer.type = CreateUInt64();
    } else {
      integer.type = CreateInt64();
    }
  }
}

void SemanticAnalyser::visit(PositionalParameter &param)
{
  param.type = CreateInt64();
  if (func_ == "str") {
    param.is_in_str = true;
    has_pos_param_ = true;
  }
  switch (param.ptype) {
    case PositionalParameterType::positional:
      if (param.n <= 0)
        LOG(ERROR, param.loc, err_)
            << "$" << std::to_string(param.n) + " is not a valid parameter";
      if (is_final_pass()) {
        std::string pstr = bpftrace_.get_param(param.n, param.is_in_str);
        auto param_int = get_int_from_str(pstr);
        if (!param_int.has_value() && !param.is_in_str) {
          LOG(ERROR, param.loc, err_)
              << "$" << param.n << " used numerically but given \"" << pstr
              << "\". Try using str($" << param.n << ").";
        }
        if (param_int && std::holds_alternative<uint64_t>(*param_int)) {
          param.type = CreateUInt64();
        }
        // string allocated in bpf stack. See codegen.
        if (param.is_in_str)
          param.type.SetAS(AddrSpace::kernel);
      }
      break;
    case PositionalParameterType::count:
      if (param.is_in_str) {
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
  string.type = CreateString(string.str.size() + 1);
  // Skip check for printf()'s format string (1st argument) and create the
  // string with the original size. This is because format string is not part of
  // bpf byte code.
  if (func_ == "printf" && func_arg_idx_ == 0)
    return;

  auto str_len = bpftrace_.config_.get(ConfigKeyInt::max_strlen);
  if (!is_compile_time_func(func_) && string.str.size() > str_len - 1) {
    LOG(ERROR, string.loc, err_)
        << "String is too long (over " << str_len << " bytes): " << string.str;
  }
  // @a = buf("hi", 2). String allocated on bpf stack. See codegen
  string.type.SetAS(AddrSpace::kernel);
}

void SemanticAnalyser::visit(StackMode &mode)
{
  auto stack_mode = bpftrace::Config::get_stack_mode(mode.mode);
  if (stack_mode.has_value()) {
    mode.type = CreateStackMode();
    mode.type.stack_type.mode = stack_mode.value();
  } else {
    mode.type = CreateNone();
    LOG(ERROR, mode.loc, err_) << "Unknown stack mode: '" + mode.mode + "'";
  }
}

void SemanticAnalyser::visit(Identifier &identifier)
{
  if (bpftrace_.enums_.count(identifier.ident) != 0) {
    const auto &enum_name = std::get<1>(bpftrace_.enums_[identifier.ident]);
    identifier.type = CreateEnum(64, enum_name);
  } else if (bpftrace_.structs.Has(identifier.ident)) {
    identifier.type = CreateRecord(identifier.ident,
                                   bpftrace_.structs.Lookup(identifier.ident));
  } else if (func_ == "sizeof" && getIntcasts().count(identifier.ident) != 0) {
    identifier.type = CreateInt(
        std::get<0>(getIntcasts().at(identifier.ident)));
  } else if (func_ == "nsecs") {
    identifier.type = CreateTimestampMode();
    if (identifier.ident == "monotonic") {
      identifier.type.ts_mode = TimestampMode::monotonic;
    } else if (identifier.ident == "boot") {
      identifier.type.ts_mode = TimestampMode::boot;
    } else if (identifier.ident == "tai") {
      identifier.type.ts_mode = TimestampMode::tai;
    } else if (identifier.ident == "sw_tai") {
      identifier.type.ts_mode = TimestampMode::sw_tai;
    } else {
      LOG(ERROR, identifier.loc, err_)
          << "Invalid timestamp mode: " << identifier.ident;
    }
  } else {
    identifier.type = CreateNone();
    LOG(ERROR, identifier.loc, err_)
        << "Unknown identifier: '" + identifier.ident + "'";
  }
}

void SemanticAnalyser::builtin_args_tracepoint(AttachPoint *attach_point,
                                               Builtin &builtin)
{
  // tracepoint wildcard expansion, part 2 of 3. This:
  // 1. expands the wildcard, then sets args to be the first matched probe.
  //    This is so that enough of the type information is available to
  //    survive the later semantic analyser checks.
  // 2. sets is_tparg so that codegen does the real type setting after
  //    expansion.
  auto matches = bpftrace_.probe_matcher_->get_matches_for_ap(*attach_point);
  if (!matches.empty()) {
    auto &match = *matches.begin();
    std::string tracepoint_struct = TracepointFormatParser::get_struct_name(
        match);
    builtin.type = CreateRecord(tracepoint_struct,
                                bpftrace_.structs.Lookup(tracepoint_struct));
    builtin.type.SetAS(attach_point->target == "syscalls" ? AddrSpace::user
                                                          : AddrSpace::kernel);
    builtin.type.MarkCtxAccess();
    builtin.type.is_tparg = true;
  }
}

ProbeType SemanticAnalyser::single_provider_type(Probe *probe)
{
  ProbeType type = ProbeType::invalid;

  for (auto *attach_point : probe->attach_points) {
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
  switch (pt) {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
    case ProbeType::fentry:
    case ProbeType::fexit:
    case ProbeType::tracepoint:
    case ProbeType::iter:
    case ProbeType::rawtracepoint:
      return AddrSpace::kernel;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::usdt:
      return AddrSpace::user;
    // case : i:ms:1 (struct x*)ctx)->x
    // Cannot decide the addrspace. Provide backward compatibility,
    // if addrspace cannot be detected.
    case ProbeType::invalid:
    case ProbeType::special:
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
  if (builtin.ident == "ctx") {
    auto probe = get_probe(builtin.loc, builtin.ident);
    if (probe == nullptr)
      return;
    ProbeType pt = probetype(probe->attach_points[0]->provider);
    libbpf::bpf_prog_type bt = progtype(pt);
    std::string func = probe->attach_points[0]->func;

    for (auto *attach_point : probe->attach_points) {
      ProbeType pt = probetype(attach_point->provider);
      libbpf::bpf_prog_type bt2 = progtype(pt);
      if (bt != bt2)
        LOG(ERROR, builtin.loc, err_)
            << "ctx cannot be used in different BPF program types: "
            << progtypeName(bt) << " and " << progtypeName(bt2);
    }
    switch (static_cast<libbpf::bpf_prog_type>(bt)) {
      case libbpf::BPF_PROG_TYPE_KPROBE:
        builtin.type = CreatePointer(CreateRecord("struct pt_regs",
                                                  bpftrace_.structs.Lookup(
                                                      "struct pt_regs")),
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
        if (pt == ProbeType::iter) {
          std::string type = "struct bpf_iter__" + func;
          builtin.type = CreatePointer(
              CreateRecord(type, bpftrace_.structs.Lookup(type)),
              AddrSpace::kernel);
          builtin.type.MarkCtxAccess();
          builtin.type.is_btftype = true;
        } else {
          LOG(ERROR, builtin.loc, err_) << "invalid program type";
        }
        break;
      default:
        LOG(ERROR, builtin.loc, err_) << "invalid program type";
        break;
    }
  } else if (builtin.ident == "pid" || builtin.ident == "tid") {
    builtin.type = CreateUInt32();
  } else if (builtin.ident == "nsecs" || builtin.ident == "elapsed" ||
             builtin.ident == "cgroup" || builtin.ident == "uid" ||
             builtin.ident == "gid" || builtin.ident == "cpu" ||
             builtin.ident == "rand" || builtin.ident == "numaid" ||
             builtin.ident == "jiffies") {
    builtin.type = CreateUInt64();
    if (builtin.ident == "cgroup" &&
        !bpftrace_.feature_->has_helper_get_current_cgroup_id()) {
      LOG(ERROR, builtin.loc, err_)
          << "BPF_FUNC_get_current_cgroup_id is not available for your kernel "
             "version";
    } else if (builtin.ident == "jiffies" &&
               !bpftrace_.feature_->has_helper_jiffies64()) {
      LOG(ERROR, builtin.loc, err_)
          << "BPF_FUNC_jiffies64 is not available for your kernel version";
    }
  } else if (builtin.ident == "curtask") {
    // Retype curtask to its original type: struct task_struct.
    builtin.type = CreatePointer(CreateRecord("struct task_struct",
                                              bpftrace_.structs.Lookup(
                                                  "struct task_struct")),
                                 AddrSpace::kernel);
  } else if (builtin.ident == "retval") {
    auto probe = get_probe(builtin.loc, builtin.ident);
    if (probe == nullptr)
      return;
    ProbeType type = single_provider_type(probe);

    if (type == ProbeType::kretprobe || type == ProbeType::uretprobe) {
      builtin.type = CreateUInt64();
    } else if (type == ProbeType::fentry || type == ProbeType::fexit) {
      auto arg = bpftrace_.structs.GetProbeArg(*probe, RETVAL_FIELD_NAME);
      if (arg) {
        builtin.type = arg->type;
        builtin.type.is_btftype = true;
      } else
        LOG(ERROR, builtin.loc, err_)
            << "Can't find a field " << RETVAL_FIELD_NAME;
    } else {
      LOG(ERROR, builtin.loc, err_)
          << "The retval builtin can only be used with 'kretprobe' and "
          << "'uretprobe' and 'fentry' probes"
          << (type == ProbeType::tracepoint ? " (try to use args.ret instead)"
                                            : "");
    }
    // For kretprobe, fentry, fexit -> AddrSpace::kernel
    // For uretprobe -> AddrSpace::user
    builtin.type.SetAS(find_addrspace(type));
  } else if (builtin.ident == "kstack") {
    builtin.type = CreateStack(true,
                               StackType{ .mode = bpftrace_.config_.get(
                                              ConfigKeyStackMode::default_) });
  } else if (builtin.ident == "ustack") {
    builtin.type = CreateStack(false,
                               StackType{ .mode = bpftrace_.config_.get(
                                              ConfigKeyStackMode::default_) });
  } else if (builtin.ident == "comm") {
    builtin.type = CreateString(COMM_SIZE);
    // comm allocated in the bpf stack. See codegen
    // Case: @=comm and strncmp(@, "name")
    builtin.type.SetAS(AddrSpace::kernel);
  } else if (builtin.ident == "func") {
    auto probe = get_probe(builtin.loc, builtin.ident);
    if (probe == nullptr)
      return;
    for (auto *attach_point : probe->attach_points) {
      ProbeType type = probetype(attach_point->provider);
      if (type == ProbeType::kprobe || type == ProbeType::kretprobe)
        builtin.type = CreateKSym();
      else if (type == ProbeType::uprobe || type == ProbeType::uretprobe)
        builtin.type = CreateUSym();
      else if (type == ProbeType::fentry || type == ProbeType::fexit) {
        if (!bpftrace_.feature_->has_helper_get_func_ip()) {
          LOG(ERROR, builtin.loc, err_)
              << "BPF_FUNC_get_func_ip not available for your kernel version";
        }
        builtin.type = CreateKSym();
      } else
        LOG(ERROR, builtin.loc, err_)
            << "The func builtin can not be used with '"
            << attach_point->provider << "' probes";

      if ((type == ProbeType::kretprobe || type == ProbeType::uretprobe) &&
          !bpftrace_.feature_->has_helper_get_func_ip()) {
        LOG(ERROR, builtin.loc, err_)
            << "The 'func' builtin is not available for " << type
            << "s on kernels without the get_func_ip BPF feature. Consider "
               "using the 'probe' builtin instead.";
      }
    }
  } else if (builtin.is_argx()) {
    auto probe = get_probe(builtin.loc, builtin.ident);
    if (probe == nullptr)
      return;
    ProbeType pt = probetype(probe->attach_points[0]->provider);
    AddrSpace addrspace = find_addrspace(pt);
    for (auto *attach_point : probe->attach_points) {
      ProbeType type = probetype(attach_point->provider);
      if (type == ProbeType::uprobe &&
          bpftrace_.config_.get(ConfigKeyBool::probe_inline))
        LOG(ERROR, builtin.loc, err_)
            << "The " + builtin.ident + " builtin can only be used when "
            << "the probe_inline config is disabled.";
      if (type != ProbeType::kprobe && type != ProbeType::uprobe &&
          type != ProbeType::usdt && type != ProbeType::rawtracepoint)
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
  } else if (!builtin.ident.compare(0, 4, "sarg") &&
             builtin.ident.size() == 5 && builtin.ident.at(4) >= '0' &&
             builtin.ident.at(4) <= '9') {
    auto probe = get_probe(builtin.loc, builtin.ident);
    if (probe == nullptr)
      return;
    ProbeType pt = probetype(probe->attach_points[0]->provider);
    AddrSpace addrspace = find_addrspace(pt);
    for (auto *attach_point : probe->attach_points) {
      ProbeType type = probetype(attach_point->provider);
      if (type != ProbeType::kprobe && type != ProbeType::uprobe)
        LOG(ERROR, builtin.loc, err_)
            << "The " + builtin.ident
            << " builtin can only be used with 'kprobes' and 'uprobes' probes";
      if (type == ProbeType::uprobe &&
          bpftrace_.config_.get(ConfigKeyBool::probe_inline))
        LOG(ERROR, builtin.loc, err_)
            << "The " + builtin.ident + " builtin can only be used when "
            << "the probe_inline config is disabled.";
      if (is_final_pass() &&
          (attach_point->address != 0 || attach_point->func_offset != 0)) {
        // If sargX values are needed when using an offset, they can be stored
        // in a map when entering the function and then referenced from an
        // offset-based probe
        LOG(WARNING, builtin.loc, out_)
            << "Using an address offset with the sargX built-in can"
               "lead to unexpected behavior ";
      }
    }
    builtin.type = CreateUInt64();
    builtin.type.SetAS(addrspace);
  } else if (builtin.ident == "probe") {
    auto probe = get_probe(builtin.loc, builtin.ident);
    if (probe == nullptr)
      return;
    size_t str_size = 0;
    for (AttachPoint *attach_point : probe->attach_points) {
      auto matches = bpftrace_.probe_matcher_->get_matches_for_ap(
          *attach_point);
      for (const auto &match : matches) {
        // No need to preserve this node, as we are just expanding to see the
        // size of the name. This could be refactored into a separate pass.
        ASTContext dummyctx;
        str_size = std::max(str_size,
                            attach_point->create_expansion_copy(dummyctx, match)
                                .name()
                                .length());
      }
    }
    builtin.type = CreateString(str_size + 1);
    probe->need_expansion = true;
  } else if (builtin.ident == "username") {
    builtin.type = CreateUsername();
  } else if (builtin.ident == "cpid") {
    if (!has_child_) {
      LOG(ERROR, builtin.loc, err_)
          << "cpid cannot be used without child command";
    }
    builtin.type = CreateUInt32();
  } else if (builtin.ident == "args") {
    auto probe = get_probe(builtin.loc, builtin.ident);
    if (probe == nullptr)
      return;
    for (auto *attach_point : probe->attach_points) {
      ProbeType type = probetype(attach_point->provider);

      if (type == ProbeType::tracepoint) {
        attach_point->expansion = ExpansionType::FULL;
        builtin_args_tracepoint(attach_point, builtin);
      }
    }

    ProbeType type = single_provider_type(probe);

    if (type == ProbeType::invalid) {
      LOG(ERROR, builtin.loc, err_)
          << "The args builtin can only be used within the context of a single "
             "probe type, e.g. \"probe1 {args}\" is valid while "
             "\"probe1,probe2 {args}\" is not.";
    } else if (type == ProbeType::fentry || type == ProbeType::fexit ||
               type == ProbeType::uprobe) {
      if (type == ProbeType::uprobe &&
          bpftrace_.config_.get(ConfigKeyBool::probe_inline))
        LOG(ERROR, builtin.loc, err_)
            << "The args builtin can only be used when "
            << "the probe_inline config is disabled.";

      auto type_name = probe->args_typename();
      builtin.type = CreateRecord(type_name,
                                  bpftrace_.structs.Lookup(type_name));
      if (builtin.type.GetFieldCount() == 0)
        LOG(ERROR, builtin.loc, err_) << "Cannot read function parameters";

      builtin.type.MarkCtxAccess();
      builtin.type.is_funcarg = true;
      builtin.type.SetAS(type == ProbeType::uprobe ? AddrSpace::user
                                                   : AddrSpace::kernel);
      // We'll build uprobe args struct on stack
      if (type == ProbeType::uprobe)
        builtin.type.is_internal = true;
    } else if (type != ProbeType::tracepoint) // no special action for
                                              // tracepoint
    {
      LOG(ERROR, builtin.loc, err_) << "The args builtin can only be used with "
                                       "tracepoint/fentry/uprobe probes ("
                                    << type << " used here)";
    }
  } else {
    builtin.type = CreateNone();
    LOG(ERROR, builtin.loc, err_)
        << "Unknown builtin variable: '" << builtin.ident << "'";
  }
}

namespace {
bool skip_key_validation(const Call &call)
{
  return call.func == "print" || call.func == "clear" || call.func == "zero" ||
         call.func == "len";
}
} // namespace

void SemanticAnalyser::visit(Call &call)
{
  // Check for unsafe-ness first. It is likely the most pertinent issue
  // (and should be at the top) for any function call.
  if (bpftrace_.safe_mode_ && is_unsafe_func(call.func)) {
    LOG(ERROR, call.loc, err_)
        << call.func << "() is an unsafe function being used in safe mode";
  }

  struct func_setter {
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

  for (size_t i = 0; i < call.vargs.size(); ++i) {
    auto &expr = *call.vargs[i];
    func_arg_idx_ = i;

    if (expr.is_map) {
      Map &map = static_cast<Map &>(expr);

      // If the map is indexed, don't skip key validation
      if (map.key_expr == nullptr) {
        // These calls expect just a map reference for the first argument
        if ((call.func == "delete" || call.func == "has_key") && i == 0) {
          map.skip_key_validation = true;
          map.is_read = false;
        } else if (skip_key_validation(call)) {
          map.skip_key_validation = true;
          map.is_read = false;
        }
      }
    }

    call.vargs[i] = dereference_if_needed(call.vargs[i]);
  }

  if (auto probe = dynamic_cast<Probe *>(top_level_node_)) {
    for (auto *ap : probe->attach_points) {
      if (!check_available(call, *ap)) {
        LOG(ERROR, call.loc, err_) << call.func << " can not be used with \""
                                   << ap->provider << "\" probes";
      }
    }
  }

  if (call.func == "hist") {
    check_assignment(call, true, false, false);
    if (!check_varargs(call, 1, 2))
      return;
    if (call.vargs.size() == 1) {
      call.vargs.push_back(ctx_.make_node<Integer>(0, call.loc)); // default
                                                                  // bits is 0
    } else {
      if (!check_arg(call, Type::integer, 1, true))
        return;
      const auto bits = bpftrace_.get_int_literal(call.vargs.at(1));
      if (!bits.has_value()) {
        // Bug here as the validity of the integer literal is already checked by
        // check_arg above.
        LOG(BUG) << call.func << ": invalid bits value";
      } else if (*bits < 0 || *bits > 5) {
        LOG(ERROR, call.loc, err_)
            << call.func << ": bits " << *bits << " must be 0..5";
      }
    }
    check_arg(call, Type::integer, 0);

    call.type = CreateHist();
  } else if (call.func == "lhist") {
    check_assignment(call, true, false, false);
    if (check_nargs(call, 4)) {
      check_arg(call, Type::integer, 0, false);
      check_arg(call, Type::integer, 1, true);
      check_arg(call, Type::integer, 2, true);
      check_arg(call, Type::integer, 3, true);
    }

    if (is_final_pass()) {
      Expression *min_arg = call.vargs.at(1);
      Expression *max_arg = call.vargs.at(2);
      Expression *step_arg = call.vargs.at(3);
      auto min = bpftrace_.get_int_literal(min_arg);
      auto max = bpftrace_.get_int_literal(max_arg);
      auto step = bpftrace_.get_int_literal(step_arg);

      if (!min.has_value()) {
        LOG(ERROR, call.loc, err_) << call.func << ": invalid min value";
        return;
      }
      if (!max.has_value()) {
        LOG(ERROR, call.loc, err_) << call.func << ": invalid max value";
        return;
      }
      if (!step.has_value()) {
        LOG(ERROR, call.loc, err_) << call.func << ": invalid step value";
        return;
      }

      if (*step <= 0) {
        LOG(ERROR, call.loc, err_)
            << "lhist() step must be >= 1 (" << *step << " provided)";
      } else {
        int buckets = (*max - *min) / *step;
        if (buckets > 1000) {
          LOG(ERROR, call.loc, err_)
              << "lhist() too many buckets, must be <= 1000 (would need "
              << buckets << ")";
        }
      }
      if (*min < 0) {
        LOG(ERROR, call.loc, err_)
            << "lhist() min must be non-negative (provided min " << *min << ")";
      }
      if (*min > *max) {
        LOG(ERROR, call.loc, err_)
            << "lhist() min must be less than max (provided min " << *min
            << " and max " << *max << ")";
      }
      if ((*max - *min) < *step) {
        LOG(ERROR, call.loc, err_)
            << "lhist() step is too large for the given range (provided step "
            << *step << " for range " << (*max - *min) << ")";
      }
    }
    call.type = CreateLhist();
  } else if (call.func == "count") {
    check_assignment(call, true, false, false);
    (void)check_nargs(call, 0);

    call.type = CreateCount(true);
  } else if (call.func == "sum") {
    bool sign = false;
    check_assignment(call, true, false, false);
    if (check_nargs(call, 1)) {
      check_arg(call, Type::integer, 0);
      sign = call.vargs.at(0)->type.IsSigned();
    }
    call.type = CreateSum(sign);
  } else if (call.func == "min") {
    bool sign = false;
    check_assignment(call, true, false, false);
    if (check_nargs(call, 1)) {
      check_arg(call, Type::integer, 0);
      sign = call.vargs.at(0)->type.IsSigned();
    }
    call.type = CreateMin(sign);
  } else if (call.func == "max") {
    bool sign = false;
    check_assignment(call, true, false, false);
    if (check_nargs(call, 1)) {
      check_arg(call, Type::integer, 0);
      sign = call.vargs.at(0)->type.IsSigned();
    }
    call.type = CreateMax(sign);
  } else if (call.func == "avg") {
    check_assignment(call, true, false, false);
    if (check_nargs(call, 1)) {
      check_arg(call, Type::integer, 0);
    }
    call.type = CreateAvg(true);
  } else if (call.func == "stats") {
    check_assignment(call, true, false, false);
    if (check_nargs(call, 1)) {
      check_arg(call, Type::integer, 0);
    }
    call.type = CreateStats(true);
  } else if (call.func == "delete") {
    check_assignment(call, false, false, false);
    if (check_varargs(call, 1, 2)) {
      if (!call.vargs.at(0)->is_map) {
        LOG(ERROR, call.vargs.at(0)->loc, err_) << DELETE_ERROR;
      } else {
        Map &map = static_cast<Map &>(*call.vargs.at(0));
        if (call.vargs.size() == 1) {
          if (map.key_expr) {
            // We're modifying the AST here to support the deprecated delete
            // API. Once we remove the old API, we can delete this.
            call.vargs.push_back(map.key_expr);
            map.key_expr = nullptr;
          } else if (is_final_pass()) {
            auto *map_key_type = get_map_key_type(map);
            if (map_key_type && !map_key_type->IsNoneTy()) {
              LOG(ERROR, call.vargs.at(0)->loc, err_) << DELETE_ERROR;
            }
          }
        } else {
          if (map.key_expr) {
            LOG(ERROR, call.vargs.at(0)->loc, err_)
                << "delete() expects a map with no keys for the first argument";
          }
          auto *map_key_type = get_map_key_type(map);
          if (map_key_type) {
            auto &arg1 = *call.vargs.at(1);
            SizedType new_key_type = create_key_type(arg1.type, arg1.loc);
            update_current_key(*map_key_type, new_key_type);
            validate_new_key(*map_key_type, new_key_type, map.ident, arg1.loc);
          }
        }
      }
    }
    call.type = CreateNone();
  } else if (call.func == "has_key") {
    if (check_varargs(call, 2, 2)) {
      auto &arg0 = *call.vargs.at(0);
      if (!arg0.is_map) {
        LOG(ERROR, arg0.loc, err_)
            << "has_key() expects the first argument to be a map";
      } else {
        Map &map = static_cast<Map &>(arg0);
        if (map.key_expr) {
          LOG(ERROR, arg0.loc, err_)
              << "has_key() expects the first argument to be a map. Not a map "
                 "value expression.";
        }
        auto *mapkey = get_map_key_type(map);
        if (mapkey) {
          if (mapkey->IsNoneTy()) {
            LOG(ERROR, arg0.loc, err_)
                << "has_key() only accepts maps that have keys. No scalar maps "
                   "e.g. `@a = 1;`";
          } else {
            auto &arg1 = *call.vargs.at(1);
            SizedType new_key_type = create_key_type(arg1.type, arg1.loc);
            update_current_key(*mapkey, new_key_type);
            validate_new_key(*mapkey, new_key_type, map.ident, arg1.loc);
          }
        }
        // Note: if the map key is null after the final pass we'll
        // get an error in the Map visitor about the whole map being undefined
        // so no need to add a second, similar error here.
      }
    }
    // TODO: this should be a bool type but that type is currently broken
    // as a value for variables and maps
    // https://github.com/bpftrace/bpftrace/issues/3502
    call.type = CreateUInt8();
  } else if (call.func == "str") {
    if (check_varargs(call, 1, 2)) {
      auto *arg = call.vargs.at(0);
      auto &t = arg->type;
      if (!t.IsIntegerTy() && !t.IsPtrTy()) {
        LOG(ERROR, call.loc, err_)
            << call.func << "() expects an integer or a pointer type as first "
            << "argument (" << t << " provided)";
      }

      auto strlen = bpftrace_.config_.get(ConfigKeyInt::max_strlen);

      if (call.vargs.size() == 2 && check_arg(call, Type::integer, 1, false)) {
        auto &size_arg = *call.vargs.at(1);
        if (size_arg.is_literal) {
          auto &integer = static_cast<Integer &>(size_arg);
          long value = integer.n;
          if (value < 0) {
            if (is_final_pass())
              LOG(ERROR, call.loc, err_)
                  << call.func << "cannot use negative length (" << value
                  << ")";
          } else if (value > static_cast<int64_t>(strlen)) {
            if (is_final_pass())
              LOG(WARNING, call.loc, out_)
                  << "length param (" << value
                  << ") is too long and will be shortened to " << strlen
                  << " bytes (see BPFTRACE_MAX_STRLEN)";
          } else {
            strlen = value;
          }
        }
      }

      call.type = CreateString(strlen);

      if (has_pos_param_) {
        if (dynamic_cast<PositionalParameter *>(arg))
          call.is_literal = true;
        else {
          auto binop = dynamic_cast<Binop *>(arg);
          if (!(binop && (dynamic_cast<PositionalParameter *>(binop->left) ||
                          dynamic_cast<PositionalParameter *>(binop->right)))) {
            // Only str($1), str($1 + CONST), or str(CONST + $1) are allowed
            LOG(ERROR, call.loc, err_)
                << call.func << "() only accepts positional parameters"
                << " directly or with a single constant offset added";
          }
        }
      }

      // Required for cases like strncmp(str($1), str(2), 4))
      call.type.SetAS(AddrSpace::kernel);
    }
    has_pos_param_ = false;
  } else if (call.func == "buf") {
    const uint64_t max_strlen = bpftrace_.config_.get(ConfigKeyInt::max_strlen);
    if (max_strlen >
        std::numeric_limits<decltype(AsyncEvent::Buf::length)>::max()) {
      LOG(ERROR, call.loc, err_)
          << "BPFTRACE_MAX_STRLEN too large to use on buffer (" << max_strlen
          << " > " << std::numeric_limits<uint32_t>::max() << ")";
    }

    if (!check_varargs(call, 1, 2))
      return;

    auto &arg = *call.vargs.at(0);
    if (is_final_pass() && !(arg.type.IsIntTy() || arg.type.IsStringTy() ||
                             arg.type.IsPtrTy() || arg.type.IsArrayTy())) {
      LOG(ERROR, call.loc, err_)
          << call.func
          << "() expects an integer, string, or array argument but saw "
          << typestr(arg.type.GetTy());
    }

    // Subtract out metadata headroom
    uint32_t max_buffer_size = max_strlen - sizeof(AsyncEvent::Buf);
    uint32_t buffer_size = max_buffer_size;

    if (call.vargs.size() == 1) {
      if (arg.type.IsArrayTy())
        buffer_size = arg.type.GetNumElements() *
                      arg.type.GetElementTy()->GetSize();
      else if (is_final_pass())
        LOG(ERROR, call.loc, err_)
            << call.func << "() expects a length argument for non-array type "
            << typestr(arg.type.GetTy());
    } else {
      if (is_final_pass())
        check_arg(call, Type::integer, 1, false);

      auto &size_arg = *call.vargs.at(1);
      if (size_arg.type.IsIntTy() && size_arg.is_literal) {
        auto value = bpftrace_.get_int_literal(&size_arg);
        if (value.has_value()) {
          if (*value < 0) {
            LOG(ERROR, call.loc, err_)
                << call.func << " cannot use negative length (" << *value
                << ")";
          }
          buffer_size = *value;
        } else
          LOG(ERROR, call.loc, err_) << call.func << ": invalid length value";
      }
    }

    if (buffer_size > max_buffer_size) {
      if (is_final_pass())
        LOG(WARNING, call.loc, out_)
            << call.func << "() length is too long and will be shortened to "
            << std::to_string(max_strlen) << " bytes (see BPFTRACE_MAX_STRLEN)";

      buffer_size = max_buffer_size;
    }

    call.type = CreateBuffer(buffer_size);
    // Consider case : $a = buf("hi", 2); $b = buf("bye", 3);  $a == $b
    // The result of buf is copied to bpf stack. Hence kernel probe read
    call.type.SetAS(AddrSpace::kernel);
  } else if (call.func == "ksym" || call.func == "usym") {
    if (check_nargs(call, 1)) {
      // allow symbol lookups on casts (eg, function pointers)
      auto &arg = *call.vargs.at(0);
      auto &type = arg.type;
      if (!type.IsIntegerTy() && !type.IsPtrTy())
        LOG(ERROR, call.loc, err_)
            << call.func << "() expects an integer or pointer argument";
    }

    if (call.func == "ksym")
      call.type = CreateKSym();
    else if (call.func == "usym")
      call.type = CreateUSym();
  } else if (call.func == "ntop") {
    if (!check_varargs(call, 1, 2))
      return;

    auto arg = call.vargs.at(0);
    if (call.vargs.size() == 2) {
      arg = call.vargs.at(1);
      check_arg(call, Type::integer, 0);
    }

    if (!arg->type.IsIntTy() && !arg->type.IsStringTy() &&
        !arg->type.IsArrayTy())
      LOG(ERROR, call.loc, err_)
          << call.func << "() expects an integer or array argument, got "
          << arg->type.GetTy();

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
  } else if (call.func == "pton") {
    if (!check_nargs(call, 1))
      return;
    std::string addr = bpftrace_.get_string_literal(call.vargs.at(0));
    int af_type, addr_size;
    // use '.' and ':' to determine the address family
    if (addr.find(".") != std::string::npos) {
      af_type = AF_INET;
      addr_size = 4;
    } else if (addr.find(":") != std::string::npos) {
      af_type = AF_INET6;
      addr_size = 16;
    } else {
      LOG(ERROR, call.loc, err_)
          << call.func
          << "() expects an string argument of an IPv4/IPv6 address, got "
          << addr;
      return;
    }

    std::vector<char> dst(addr_size);
    auto ret = inet_pton(af_type, addr.c_str(), dst.data());
    if (ret != 1) {
      LOG(ERROR, call.loc, err_)
          << call.func << "() expects a valid IPv4/IPv6 address, got " << addr;
      return;
    }

    auto elem_type = CreateUInt8();
    call.type = CreateArray(addr_size, elem_type);
    call.type.SetAS(AddrSpace::kernel);
    call.type.is_internal = true;
  } else if (call.func == "join") {
    check_assignment(call, false, false, false);
    call.type = CreateNone();

    if (!check_varargs(call, 1, 2))
      return;

    if (!is_final_pass())
      return;

    auto &arg = *call.vargs.at(0);
    if (!(arg.type.IsIntTy() || arg.type.IsPtrTy())) {
      LOG(ERROR, call.loc, err_) << "() only supports int or pointer arguments"
                                 << " (" << arg.type.GetTy() << " provided)";
    }

    if (call.vargs.size() > 1)
      check_arg(call, Type::string, 1, true);
  } else if (call.func == "reg") {
    if (check_nargs(call, 1)) {
      if (check_arg(call, Type::string, 0, true)) {
        auto reg_name = bpftrace_.get_string_literal(call.vargs.at(0));
        int offset = arch::offset(reg_name);
        ;
        if (offset == -1) {
          LOG(ERROR, call.loc, err_)
              << "'" << reg_name
              << "' is not a valid register on this architecture"
              << " (" << arch::name() << ")";
        }
      }
    }
    call.type = CreateUInt64();
    if (auto probe = dynamic_cast<Probe *>(top_level_node_)) {
      ProbeType pt = single_provider_type(probe);
      // In case of different attach_points, Set the addrspace to none.
      call.type.SetAS(find_addrspace(pt));
    } else {
      // Assume kernel space for data in subprogs
      call.type.SetAS(AddrSpace::kernel);
    }
  } else if (call.func == "kaddr") {
    if (check_nargs(call, 1)) {
      check_arg(call, Type::string, 0, true);
    }
    call.type = CreateUInt64();
    call.type.SetAS(AddrSpace::kernel);
  } else if (call.func == "percpu_kaddr") {
    if (check_varargs(call, 1, 2)) {
      check_arg(call, Type::string, 0, true);
      if (call.vargs.size() == 2)
        check_arg(call, Type::integer, 1, false);

      auto symbol = bpftrace_.get_string_literal(call.vargs.at(0));
      if (bpftrace_.btf_->get_var_type(symbol).IsNoneTy()) {
        LOG(ERROR, call.loc, err_)
            << "Could not resolve variable \"" << symbol << "\" from BTF";
      }
    }
    call.type = CreateUInt64();
    call.type.SetAS(AddrSpace::kernel);
  } else if (call.func == "uaddr") {
    auto probe = get_probe(call.loc, call.func);
    if (probe == nullptr)
      return;

    if (!check_nargs(call, 1))
      return;
    if (!(check_arg(call, Type::string, 0, true) && check_symbol(call, 0)))
      return;

    std::vector<int> sizes;
    auto name = bpftrace_.get_string_literal(call.vargs.at(0));
    for (auto *ap : probe->attach_points) {
      struct symbol sym = {};
      int err = bpftrace_.resolve_uname(name, &sym, ap->target);
      if (err < 0 || sym.address == 0) {
        LOG(ERROR, call.loc, err_)
            << "Could not resolve symbol: " << ap->target << ":" << name;
      }
      sizes.push_back(sym.size);
    }

    for (size_t i = 1; i < sizes.size(); i++) {
      if (sizes.at(0) != sizes.at(i)) {
        LOG(ERROR, call.loc, err_)
            << "Symbol size mismatch between probes. Symbol \"" << name
            << "\" has size " << sizes.at(0) << " for probe \""
            << probe->attach_points.at(0)->name() << "\" but size "
            << sizes.at(i) << " for probe \""
            << probe->attach_points.at(i)->name() << "\"";
      }
    }
    size_t pointee_size = 0;
    switch (sizes.at(0)) {
      case 1:
      case 2:
      case 4:
        pointee_size = sizes.at(0) * 8;
        break;
      default:
        pointee_size = 64;
    }
    call.type = CreatePointer(CreateInt(pointee_size), AddrSpace::user);
  } else if (call.func == "cgroupid") {
    if (check_nargs(call, 1)) {
      check_arg(call, Type::string, 0, true);
    }
    call.type = CreateUInt64();
  } else if (call.func == "printf" || call.func == "system" ||
             call.func == "cat" || call.func == "debugf") {
    check_assignment(call, false, false, false);
    if (check_varargs(call, 1, 128)) {
      check_arg(call, Type::string, 0, true);
      if (is_final_pass()) {
        // NOTE: the same logic can be found in the resource_analyser pass
        auto &fmt_arg = *call.vargs.at(0);
        String &fmt = static_cast<String &>(fmt_arg);
        std::vector<Field> args;
        for (auto iter = call.vargs.begin() + 1; iter != call.vargs.end();
             iter++) {
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
              .bitfield = std::nullopt,
          });
        }
        std::string msg = validate_format_string(fmt.str, args, call.func);
        if (msg != "") {
          LOG(ERROR, call.loc, err_) << msg;
        }
      }
    }
    if (call.func == "debugf" && is_final_pass()) {
      LOG(WARNING, call.loc, out_)
          << "The debugf() builtin is not recommended for production use. For "
             "more information see bpf_trace_printk in bpf-helpers(7).";
    }

    call.type = CreateNone();
  } else if (call.func == "exit") {
    check_assignment(call, false, false, false);

    if (!check_varargs(call, 0, 1))
      return;

    if (call.vargs.size() == 1)
      check_arg(call, Type::integer, 0);
  } else if (call.func == "print") {
    check_assignment(call, false, false, false);
    if (in_loop() && is_final_pass() && call.vargs.at(0)->is_map) {
      LOG(WARNING, call.loc, out_)
          << "Due to it's asynchronous nature using 'print()' in a loop can "
             "lead to unexpected behavior. The map will likely be updated "
             "before the runtime can 'print' it.";
    }
    if (check_varargs(call, 1, 3)) {
      auto &arg = *call.vargs.at(0);
      if (arg.is_map) {
        Map &map = static_cast<Map &>(arg);
        if (map.key_expr) {
          if (call.vargs.size() > 1) {
            LOG(ERROR, call.loc, err_) << "Single-value (i.e. indexed) map "
                                          "print cannot take additional "
                                          "arguments.";
          } else if (map.type.IsMultiOutputMapTy()) {
            LOG(ERROR, call.loc, err_)
                << "Map type " << map.type
                << " cannot print the value of individual keys. You must print "
                   "the whole map.";
          }
        }

        if (is_final_pass()) {
          if (call.vargs.size() > 1)
            check_arg(call, Type::integer, 1, true);
          if (call.vargs.size() > 2)
            check_arg(call, Type::integer, 2, true);
          if (map.type.IsStatsTy() && call.vargs.size() > 1) {
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
      else if (arg.type.IsPrintableTy()) {
        if (call.vargs.size() != 1)
          LOG(ERROR, call.loc, err_)
              << "Non-map print() only takes 1 argument, " << call.vargs.size()
              << " found";
      } else {
        if (is_final_pass())
          LOG(ERROR, call.loc, err_) << arg.type << " type passed to "
                                     << call.func << "() is not printable";
      }
    }
  } else if (call.func == "cgroup_path") {
    call.type = CreateCgroupPath();
    if (check_varargs(call, 1, 2)) {
      check_arg(call, Type::integer, 0, false);
      call.vargs.size() > 1 && check_arg(call, Type::string, 1, false);
    }
  } else if (call.func == "clear") {
    check_assignment(call, false, false, false);
    if (check_nargs(call, 1)) {
      auto &arg = *call.vargs.at(0);
      if (!arg.is_map)
        LOG(ERROR, call.loc, err_) << "clear() expects a map to be provided";
      else {
        Map &map = static_cast<Map &>(arg);
        if (map.key_expr) {
          LOG(ERROR, call.loc, err_)
              << "The map passed to " << call.func << "() should not be "
              << "indexed by a key";
        }
      }
    }
  } else if (call.func == "zero") {
    check_assignment(call, false, false, false);
    if (check_nargs(call, 1)) {
      auto &arg = *call.vargs.at(0);
      if (!arg.is_map)
        LOG(ERROR, call.loc, err_) << "zero() expects a map to be provided";
      else {
        Map &map = static_cast<Map &>(arg);
        if (map.key_expr) {
          LOG(ERROR, call.loc, err_)
              << "The map passed to " << call.func << "() should not be "
              << "indexed by a key";
        }
      }
    }
  } else if (call.func == "len") {
    if (check_nargs(call, 1)) {
      auto &arg = *call.vargs.at(0);
      if (arg.is_map) {
        Map &map = static_cast<Map &>(arg);
        if (map.key_expr) {
          LOG(ERROR, call.loc, err_)
              << "The map passed to " << call.func << "() should not be "
              << "indexed by a key";
        }
      } else if (!arg.type.IsStack())
        LOG(ERROR, call.loc, err_)
            << "len() expects a map or stack to be provided";
      call.type = CreateInt64();
    }
  } else if (call.func == "time") {
    check_assignment(call, false, false, false);
    if (check_varargs(call, 0, 1)) {
      if (is_final_pass()) {
        if (call.vargs.size() > 0)
          check_arg(call, Type::string, 0, true);
      }
    }
  } else if (call.func == "strftime") {
    call.type = CreateTimestamp();
    if (check_varargs(call, 2, 2) && is_final_pass() &&
        check_arg(call, Type::string, 0, true) &&
        check_arg(call, Type::integer, 1, false)) {
      auto &arg = *call.vargs.at(1);
      call.type.ts_mode = arg.type.ts_mode;
      if (call.type.ts_mode == TimestampMode::monotonic) {
        LOG(ERROR, call.loc, err_)
            << "strftime() can not take a monotonic timestamp";
      }
    }
  } else if (call.func == "kstack") {
    check_stack_call(call, true);
  } else if (call.func == "ustack") {
    check_stack_call(call, false);
  } else if (call.func == "signal") {
    if (!bpftrace_.feature_->has_helper_send_signal()) {
      LOG(ERROR, call.loc, err_)
          << "BPF_FUNC_send_signal not available for your kernel version";
    }

    check_assignment(call, false, false, false);

    if (!check_varargs(call, 1, 1)) {
      return;
    }

    auto &arg = *call.vargs.at(0);
    if (arg.type.IsStringTy() && arg.is_literal) {
      auto sig = bpftrace_.get_string_literal(&arg);
      if (signal_name_to_num(sig) < 1) {
        LOG(ERROR, call.loc, err_) << sig << " is not a valid signal";
      }
    } else if (arg.type.IsIntTy() && arg.is_literal) {
      auto sig = bpftrace_.get_int_literal(&arg);
      if (!sig.has_value())
        LOG(ERROR, call.loc, err_) << call.func << ": invalid signal value";
      else if (*sig < 1 || *sig > 64) {
        LOG(ERROR, call.loc, err_)
            << std::to_string(*sig)
            << " is not a valid signal, allowed range: [1,64]";
      }
    } else if (!arg.type.IsIntTy()) {
      LOG(ERROR, call.loc, err_)
          << "signal only accepts string literals or integers";
    }
  } else if (call.func == "path") {
    auto probe = get_probe(call.loc, call.func);
    if (probe == nullptr)
      return;

    if (!bpftrace_.feature_->has_d_path()) {
      LOG(ERROR, call.loc, err_)
          << "BPF_FUNC_d_path not available for your kernel version";
    }

    if (check_varargs(call, 1, 2)) {
      // Argument for path can be both record and pointer.
      // It's pointer when it's passed directly from the probe
      // argument, like: path(args.path))
      // It's record when it's referenced as object pointer
      // member, like: path(args.filp->f_path))
      if (!check_arg(call, Type::record, 0, false, false) &&
          !check_arg(call, Type::pointer, 0, false, false)) {
        auto &arg = *call.vargs.at(0);

        LOG(ERROR, call.loc, err_)
            << "path() only supports pointer or record argument ("
            << arg.type.GetTy() << " provided)";
      }

      auto call_type_size = bpftrace_.config_.get(ConfigKeyInt::max_strlen);
      if (call.vargs.size() == 2) {
        if (check_arg(call, Type::integer, 1, true)) {
          auto size = bpftrace_.get_int_literal(call.vargs.at(1));
          if (size.has_value()) {
            if (size < 0)
              LOG(ERROR, call.loc, err_)
                  << "Builtin path requires a non-negative size";
            call_type_size = size.value();
          } else {
            LOG(ERROR, call.loc, err_) << call.func << ": invalid size value";
          }
        }
      }

      call.type = SizedType(Type::string, call_type_size);
    }

    for (auto *attach_point : probe->attach_points) {
      ProbeType type = probetype(attach_point->provider);
      if (type != ProbeType::fentry && type != ProbeType::fexit &&
          type != ProbeType::iter)
        LOG(ERROR, call.loc, err_) << "The path function can only be used with "
                                   << "'fentry', 'fexit', 'iter' probes";
    }
  } else if (call.func == "strerror") {
    call.type = CreateStrerror();
    if (check_nargs(call, 1))
      check_arg(call, Type::integer, 0, false);
  } else if (call.func == "strncmp") {
    if (check_nargs(call, 3)) {
      check_arg(call, Type::string, 0);
      check_arg(call, Type::string, 1);
      if (check_arg(call, Type::integer, 2, true)) {
        auto size = bpftrace_.get_int_literal(call.vargs.at(2));
        if (size.has_value()) {
          if (size < 0)
            LOG(ERROR, call.loc, err_)
                << "Builtin strncmp requires a non-negative size";
        } else
          LOG(ERROR, call.loc, err_) << call.func << ": invalid size value";
      }
    }
    call.type = CreateUInt64();
  } else if (call.func == "strcontains") {
    static constexpr auto warning = R"(
strcontains() is known to have verifier complexity issues when the product of both string sizes is larger than ~2000 bytes.

If you're seeing errors, try clamping the string sizes. For example:
* `str($ptr, 16)`
* `path($ptr, 16)`
)";

    if (check_nargs(call, 2)) {
      check_arg(call, Type::string, 0);
      check_arg(call, Type::string, 1);

      if (is_final_pass()) {
        auto arg0_sz = call.vargs.at(0)->type.GetSize();
        auto arg1_sz = call.vargs.at(1)->type.GetSize();
        if (arg0_sz * arg1_sz > 2000) {
          LOG(WARNING, call.loc, out_) << warning;
        }
      }
    }
    call.type = CreateUInt64();
  } else if (call.func == "override") {
    auto probe = get_probe(call.loc, call.func);
    if (probe == nullptr)
      return;

    if (!bpftrace_.feature_->has_helper_override_return()) {
      LOG(ERROR, call.loc, err_)
          << "BPF_FUNC_override_return not available for your kernel version";
    }

    check_assignment(call, false, false, false);
    if (check_varargs(call, 1, 1)) {
      check_arg(call, Type::integer, 0, false);
    }
    for (auto *attach_point : probe->attach_points) {
      ProbeType type = probetype(attach_point->provider);
      if (type != ProbeType::kprobe) {
        LOG(ERROR, call.loc, err_)
            << call.func << " can only be used with kprobes.";
      }
    }
  } else if (call.func == "kptr" || call.func == "uptr") {
    if (!check_nargs(call, 1))
      return;

    // kptr should accept both integer or pointer. Consider case: kptr($1)
    auto &arg = *call.vargs.at(0);
    if (!arg.type.IsIntTy() && !arg.type.IsPtrTy()) {
      LOG(ERROR, call.loc, err_) << call.func << "() only supports "
                                 << "integer or pointer arguments ("
                                 << arg.type.GetTy() << " provided)";
      return;
    }

    auto as = (call.func == "kptr" ? AddrSpace::kernel : AddrSpace::user);
    call.type = call.vargs.front()->type;
    call.type.SetAS(as);
  } else if (call.func == "macaddr") {
    if (!check_nargs(call, 1))
      return;

    auto &arg = call.vargs.at(0);

    if (!arg->type.IsIntTy() && !arg->type.IsArrayTy() &&
        !arg->type.IsByteArray() && !arg->type.IsPtrTy())
      LOG(ERROR, call.loc, err_)
          << call.func << "() only supports array or pointer arguments"
          << " (" << arg->type.GetTy() << " provided)";

    auto type = arg->type;
    if ((type.IsArrayTy() || type.IsByteArray()) && type.GetSize() != 6)
      LOG(ERROR, call.loc, err_)
          << call.func << "() argument must be 6 bytes in size";

    if (type.IsStringTy() && arg->is_literal)
      LOG(ERROR, call.loc, err_)
          << call.func << "() does not support literal string arguments";

    call.type = CreateMacAddress();
  } else if (call.func == "unwatch") {
    if (check_nargs(call, 1))
      check_arg(call, Type::integer, 0);

    // Return type cannot be used
    call.type = SizedType(Type::none, 0);
  } else if (call.func == "bswap") {
    if (!check_nargs(call, 1))
      return;

    Expression *arg = call.vargs.at(0);
    if (!arg->type.IsIntTy()) {
      LOG(ERROR, call.loc, err_)
          << call.func << "() only supports integer arguments ("
          << arg->type.GetTy() << " provided)";
      return;
    }

    call.type = CreateUInt(arg->type.GetIntBitWidth());
  } else if (call.func == "skboutput") {
    if (!bpftrace_.feature_->has_skb_output()) {
      LOG(ERROR, call.loc, err_)
          << "BPF_FUNC_skb_output is not available for your kernel "
             "version";
    }

    check_assignment(call, false, true, false);
    if (check_nargs(call, 4)) {
      if (is_final_pass()) {
        // pcap file name
        check_arg(call, Type::string, 0, true);
        // *skb
        check_arg(call, Type::pointer, 1, false);
        // cap length
        check_arg(call, Type::integer, 2, false);
        // cap offset, default is 0
        // some tracepoints like dev_queue_xmit will output ethernet header, set
        // offset to 14 bytes can exclude this header
        check_arg(call, Type::integer, 3, false);
      }
    }
    call.type = CreateUInt32();
  } else if (call.func == "nsecs") {
    if (check_varargs(call, 0, 1)) {
      call.type = CreateUInt64();
      call.type.ts_mode = TimestampMode::boot;
      if (call.vargs.size() == 1 && check_arg(call, Type::timestamp_mode, 0)) {
        call.type.ts_mode = call.vargs.at(0)->type.ts_mode;
      }

      if (call.type.ts_mode == TimestampMode::tai &&
          !bpftrace_.feature_->has_helper_ktime_get_tai_ns()) {
        LOG(ERROR, call.loc, err_)
            << "Kernel does not support tai timestamp, please try sw_tai";
      }
      if (call.type.ts_mode == TimestampMode::sw_tai &&
          !bpftrace_.delta_taitime_.has_value()) {
        LOG(ERROR, call.loc, err_) << "Failed to initialize sw_tai in "
                                      "userspace. This is very unexpected.";
      }
    }
  } else {
    LOG(ERROR, call.loc, err_) << "Unknown function: '" << call.func << "'";
    call.type = CreateNone();
  }
}

void SemanticAnalyser::visit(Sizeof &szof)
{
  szof.type = CreateUInt64();
  if (szof.expr) {
    szof.expr = dereference_if_needed(szof.expr);
    szof.argtype = szof.expr->type;
  }
  resolve_struct_type(szof.argtype, szof.loc);
}

void SemanticAnalyser::visit(Offsetof &offof)
{
  offof.type = CreateUInt64();
  if (offof.expr) {
    offof.expr = dereference_if_needed(offof.expr);
    offof.record = offof.expr->type;
  }

  resolve_struct_type(offof.record, offof.loc);

  // Check if all sub-fields are present.
  SizedType record = offof.record;
  for (const auto &field : offof.field) {
    if (!record.IsRecordTy()) {
      LOG(ERROR, offof.loc, err_) << "'" << record << "' "
                                  << "is not a record type.";
    } else if (!bpftrace_.structs.Has(record.GetName())) {
      LOG(ERROR, offof.loc, err_)
          << "'" << record.GetName() << "' does not exist.";
    } else if (!record.HasField(field)) {
      LOG(ERROR, offof.loc, err_) << "'" << record.GetName() << "' "
                                  << "has no field named "
                                  << "'" << field << "'";
    } else {
      // Get next sub-field
      record = record.GetField(field).type;
    }
  }
}

void SemanticAnalyser::check_stack_call(Call &call, bool kernel)
{
  call.type = CreateStack(kernel);
  if (!check_varargs(call, 0, 2)) {
    return;
  }

  StackType stack_type;
  stack_type.mode = bpftrace_.config_.get(ConfigKeyStackMode::default_);

  switch (call.vargs.size()) {
    case 0:
      break;
    case 1: {
      auto &arg = *call.vargs.at(0);
      // If we have a single argument it can be either
      // stack-mode or stack-size
      if (arg.type.IsStackModeTy()) {
        if (check_arg(call, Type::stack_mode, 0, true))
          stack_type.mode = static_cast<StackMode &>(arg).type.stack_type.mode;
      } else {
        if (check_arg(call, Type::integer, 0, true)) {
          auto limit = bpftrace_.get_int_literal(&arg);
          if (limit.has_value())
            stack_type.limit = *limit;
          else
            LOG(ERROR, call.loc, err_) << call.func << ": invalid limit value";
        }
      }
      break;
    }
    case 2: {
      if (check_arg(call, Type::stack_mode, 0, true)) {
        auto &mode_arg = *call.vargs.at(0);
        stack_type.mode =
            static_cast<StackMode &>(mode_arg).type.stack_type.mode;
      }

      if (check_arg(call, Type::integer, 1, true)) {
        auto &limit_arg = call.vargs.at(1);
        auto limit = bpftrace_.get_int_literal(limit_arg);
        if (limit.has_value())
          stack_type.limit = *limit;
        else
          LOG(ERROR, call.loc, err_) << call.func << ": invalid limit value";
      }
      break;
    }
    default:
      LOG(ERROR, call.loc, err_) << "Invalid number of arguments";
      break;
  }
  if (stack_type.limit > MAX_STACK_SIZE) {
    LOG(ERROR, call.loc, err_)
        << call.func << "([int limit]): limit shouldn't exceed "
        << MAX_STACK_SIZE << ", " << stack_type.limit << " given";
  }
  call.type = CreateStack(kernel, stack_type);
}

Probe *SemanticAnalyser::get_probe(const location &loc, std::string name)
{
  auto probe = dynamic_cast<Probe *>(top_level_node_);
  if (probe == nullptr) {
    // Attempting to use probe-specific feature in non-probe context
    if (name.empty()) {
      LOG(ERROR, loc, err_) << "Feature not supported outside probe";
    } else {
      LOG(ERROR, loc, err_)
          << "Builtin " << name << " not supported outside probe";
    }
  }

  return probe;
}

void SemanticAnalyser::validate_map_key(const SizedType &key,
                                        const location &loc)
{
  if (key.IsPtrTy() && key.IsCtxAccess()) {
    // map functions only accepts a pointer to a element in the stack
    LOG(ERROR, loc, err_) << "context cannot be used as a map key";
  }

  if (key.IsHistTy() || key.IsLhistTy() || key.IsStatsTy()) {
    LOG(ERROR, loc, err_) << key << " cannot be used as a map key";
  }

  if (is_final_pass() && key.IsNoneTy()) {
    LOG(ERROR, loc, err_) << "Invalid expression for assignment: ";
  }
}

void SemanticAnalyser::visit(Map &map)
{
  SizedType new_key_type = CreateNone();
  bool key_is_map = false;
  if (map.key_expr) {
    map.key_expr = dereference_if_needed(map.key_expr);
    key_is_map = map.key_expr->is_map;
    new_key_type = create_key_type(map.key_expr->type, map.key_expr->loc);
  }

  if (!map.skip_key_validation) {
    if (const auto &key = map_key_.find(map.ident); key != map_key_.end()) {
      if (map.key_expr) {
        update_current_key(key->second, new_key_type);
        validate_new_key(key->second, new_key_type, map.ident, map.loc);
      } else {
        if (!key->second.IsNoneTy()) {
          LOG(ERROR, map.loc, err_)
              << "Argument mismatch for " << map.ident << ": "
              << "trying to access with no arguments when map expects "
                 "arguments: "
                 "'"
              << key->second << "'";
        }
      }
    } else {
      // If the key used is a map, we might not have the type of it yet
      // e.g. `BEGIN { @mymap[@i] = "hello"; @i = 1; }`
      if (!key_is_map || !new_key_type.IsNoneTy()) {
        map_key_.insert({ map.ident, new_key_type });
      }
    }
  }

  auto search_val = map_val_.find(map.ident);
  if (search_val != map_val_.end()) {
    map.type = search_val->second;

    if (map.is_read && map.type.IsCastableMapTy() &&
        !bpftrace_.feature_->has_helper_map_lookup_percpu_elem()) {
      LOG(ERROR, map.loc, err_)
          << "Missing required kernel feature: map_lookup_percpu_elem";
    }
  } else {
    // If there is no record of any assignment after the first pass
    // then it's safe to say this map is undefined
    if (!is_first_pass()) {
      LOG(ERROR, map.loc, err_) << "Undefined map: " << map.ident;
    }
    pass_tracker_.inc_num_unresolved();
    map.type = CreateNone();
  }

  auto map_key_search_val = map_key_.find(map.ident);
  if (map_key_search_val != map_key_.end()) {
    map.key_type = map_key_search_val->second;
  } else {
    map.key_type = CreateNone();
  }
}

void SemanticAnalyser::visit(Variable &var)
{
  if (auto *found = find_variable(var.ident)) {
    var.type = found->type;
    if (!found->was_assigned) {
      LOG(WARNING, var.loc, out_)
          << "Variable used before it was assigned: " << var.ident;
    }
    return;
  }

  LOG(ERROR, var.loc, err_)
      << "Undefined or undeclared variable: " << var.ident;
  var.type = CreateNone();
}

void SemanticAnalyser::visit(ArrayAccess &arr)
{
  arr.expr = dereference_if_needed(arr.expr);
  arr.indexpr = dereference_if_needed(arr.indexpr);

  SizedType &type = arr.expr->type;
  SizedType &indextype = arr.indexpr->type;

  if (is_final_pass()) {
    if (!type.IsArrayTy() && !type.IsPtrTy()) {
      LOG(ERROR, arr.loc, err_) << "The array index operator [] can only be "
                                   "used on arrays and pointers, found "
                                << type.GetTy() << ".";
      return;
    }

    if (type.IsPtrTy() && type.GetPointeeTy()->GetSize() == 0) {
      LOG(ERROR, arr.loc, err_) << "The array index operator [] cannot be used "
                                   "on a pointer to an unsized type (void *).";
    }

    if (indextype.IsIntTy() && arr.indexpr->is_literal) {
      if (type.IsArrayTy()) {
        auto index = bpftrace_.get_int_literal(arr.indexpr);
        if (index.has_value()) {
          size_t num = type.GetNumElements();
          if (num != 0 && static_cast<size_t>(*index) >= num)
            LOG(ERROR, arr.loc, err_)
                << "the index " << *index
                << " is out of bounds for array of size " << num;
        } else
          LOG(ERROR, arr.loc, err_) << "invalid index expression";
      }
    } else {
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

  // BPF verifier cannot track BTF information for double pointers so we cannot
  // propagate is_btftype for arrays of pointers and we need to reset it on the
  // array type as well. Indexing a pointer as an array also can't be verified,
  // so the same applies there.
  if (arr.type.IsPtrTy() || type.IsPtrTy())
    type.is_btftype = false;
  arr.type.is_btftype = type.is_btftype;
}

void SemanticAnalyser::binop_int(Binop &binop)
{
  bool lsign = binop.left->type.IsSigned();
  bool rsign = binop.right->type.IsSigned();

  auto left = binop.left;
  auto right = binop.right;
  auto left_literal = bpftrace_.get_int_literal(left);
  auto right_literal = bpftrace_.get_int_literal(right);

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
    if (lsign && !rsign && left_literal && *left_literal >= 0) {
      lsign = false;
    }
    // The reverse (10 < a) should also hold
    else if (!lsign && rsign && right_literal && *right_literal >= 0) {
      rsign = false;
    } else {
      switch (binop.op) {
        case Operator::EQ:
        case Operator::NE:
        case Operator::LE:
        case Operator::GE:
        case Operator::LT:
        case Operator::GT:
          LOG(WARNING, binop.loc, out_)
              << "comparison of integers of different signs: '" << left->type
              << "' and '" << right->type << "'"
              << " can lead to undefined behavior";
          break;
        case Operator::PLUS:
        case Operator::MINUS:
        case Operator::MUL:
        case Operator::DIV:
        case Operator::MOD:
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
  if (binop.op == Operator::DIV || binop.op == Operator::MOD) {
    // Convert operands to unsigned if possible
    if (lsign && left_literal && *left_literal >= 0)
      lsign = false;
    if (rsign && right_literal && *right_literal >= 0)
      rsign = false;

    // If they're still signed, we have to warn
    if (lsign || rsign) {
      LOG(WARNING, binop.loc, out_) << "signed operands for '" << opstr(binop)
                                    << "' can lead to undefined behavior "
                                    << "(cast to unsigned to silence warning)";
    }
  }

  if (func_ == "str") {
    // Check if one of the operands is a positional parameter
    // The other one should be a constant offset
    auto pos_param = dynamic_cast<PositionalParameter *>(left);
    auto offset = dynamic_cast<Integer *>(right);
    if (!pos_param) {
      pos_param = dynamic_cast<PositionalParameter *>(right);
      offset = dynamic_cast<Integer *>(left);
    }

    if (pos_param) {
      auto len = bpftrace_.get_param(pos_param->n, true).length();
      if (!offset || binop.op != Operator::PLUS || offset->n < 0 ||
          static_cast<size_t>(offset->n) > len) {
        LOG(ERROR, binop.loc + binop.right->loc, err_)
            << "only addition of a single constant less or equal to the "
            << "length of $" << pos_param->n << " (which is " << len << ")"
            << " is allowed inside str()";
      }
    }
  }
}

void SemanticAnalyser::binop_array(Binop &binop)
{
  auto &lht = binop.left->type;
  auto &rht = binop.right->type;
  if (binop.op != Operator::EQ && binop.op != Operator::NE) {
    LOG(ERROR, binop.loc, err_)
        << "The " << opstr(binop) << " operator cannot be used on arrays.";
  }

  if (lht.GetNumElements() != rht.GetNumElements()) {
    LOG(ERROR, binop.loc, err_)
        << "Only arrays of same size support comparison operators.";
  }

  if (!lht.GetElementTy()->IsIntegerTy() || lht != rht) {
    LOG(ERROR, binop.loc, err_)
        << "Only arrays of same sized integer support comparison operators.";
  }
}

void SemanticAnalyser::binop_ptr(Binop &binop)
{
  auto &lht = binop.left->type;
  auto &rht = binop.right->type;

  bool left_is_ptr = lht.IsPtrTy();
  auto &ptr = left_is_ptr ? lht : rht;
  auto &other = left_is_ptr ? rht : lht;

  bool compare = false;
  bool logical = false;

  // Do what C does
  switch (binop.op) {
    case Operator::EQ:
    case Operator::NE:
    case Operator::LE:
    case Operator::GE:
    case Operator::LT:
    case Operator::GT:
      compare = true;
      break;
    case Operator::LAND:
    case Operator::LOR:
      logical = true;
      break;
    default:;
  }

  auto invalid_op = [&binop, this, &lht, &rht]() {
    LOG(ERROR, binop.loc, err_)
        << "The " << opstr(binop)
        << " operator can not be used on expressions of types " << lht << ", "
        << rht;
  };

  // Binop on two pointers
  if (other.IsPtrTy()) {
    if (compare) {
      binop.type = CreateUInt(64);

      if (is_final_pass()) {
        auto le = lht.GetPointeeTy();
        auto re = rht.GetPointeeTy();
        if (*le != *re) {
          LOG(WARNING, binop.left->loc + binop.right->loc, out_)
              << "comparison of distinct pointer types ('" << *le << ", '"
              << *re << "')";
        }
      }
    } else if (logical) {
      binop.type = CreateUInt(64);
    } else {
      invalid_op();
    }
  }
  // Binop on a pointer and int
  else if (other.IsIntTy()) {
    // sum is associative but minus only works with pointer on the left hand
    // side
    if (binop.op == Operator::MINUS && !left_is_ptr)
      invalid_op();
    else if (binop.op == Operator::PLUS || binop.op == Operator::MINUS)
      binop.type = CreatePointer(*ptr.GetPointeeTy(), ptr.GetAS());
    else if (compare || logical)
      binop.type = CreateInt(64);
    else
      invalid_op();
  }
  // Might need an additional pass to resolve the type
  else if (other.IsNoneTy()) {
    if (is_final_pass()) {
      invalid_op();
    }
  }
  // Binop on a pointer and something else
  else {
    invalid_op();
  }
}

void SemanticAnalyser::visit(Binop &binop)
{
  binop.left = dereference_if_needed(binop.left);
  binop.right = dereference_if_needed(binop.right);

  auto &lht = binop.left->type;
  auto &rht = binop.right->type;
  bool lsign = binop.left->type.IsSigned();
  bool rsign = binop.right->type.IsSigned();
  bool is_int_binop = (lht.IsCastableMapTy() || lht.IsIntTy()) &&
                      (rht.IsCastableMapTy() || rht.IsIntTy());

  if (lht.IsPtrTy() || rht.IsPtrTy()) {
    binop_ptr(binop);
    return;
  }

  bool is_signed = lsign && rsign;
  switch (binop.op) {
    case Operator::LEFT:
    case Operator::RIGHT:
      is_signed = lsign;
      break;
    default:
      break;
  }

  if (is_int_binop) {
    // Implicit size promotion to larger of the two
    auto size = std::max(lht.GetSize(), rht.GetSize());
    binop.type = CreateInteger(size * 8, is_signed);
  } else {
    // Default type - will be overriden below as necessary
    binop.type = CreateInteger(64, is_signed);
  }

  auto addr_lhs = binop.left->type.GetAS();
  auto addr_rhs = binop.right->type.GetAS();

  // if lhs or rhs has different addrspace (not none), then set the
  // addrspace to none. This preserves the behaviour for x86.
  if (addr_lhs != addr_rhs && addr_lhs != AddrSpace::none &&
      addr_rhs != AddrSpace::none) {
    if (is_final_pass())
      LOG(WARNING, binop.loc, out_) << "Addrspace mismatch";
    binop.type.SetAS(AddrSpace::none);
  }
  // Associativity from left to right for binary operator
  else if (addr_lhs != AddrSpace::none) {
    binop.type.SetAS(addr_lhs);
  } else {
    // In case rhs is none, then this triggers warning in selectProbeReadHelper.
    binop.type.SetAS(addr_rhs);
  }

  if (!is_final_pass()) {
    return;
  }

  if (is_int_binop) {
    binop_int(binop);
  } else if (lht.IsArrayTy() && rht.IsArrayTy()) {
    binop_array(binop);
  } else if (lht.IsPtrTy() || rht.IsPtrTy()) {
    // This case is caught earlier, just here for readability of the if/else
    // flow
  }
  // Compare type here, not the sized type as we it needs to work on strings of
  // different lengths
  else if (lht.GetTy() != rht.GetTy()) {
    LOG(ERROR, binop.left->loc + binop.right->loc, err_)
        << "Type mismatch for '" << opstr(binop) << "': comparing '" << lht
        << "' with '" << rht << "'";
  }
  // Also allow combination like reg("sp") + 8
  else if (binop.op != Operator::EQ && binop.op != Operator::NE) {
    LOG(ERROR, binop.loc, err_)
        << "The " << opstr(binop)
        << " operator can not be used on expressions of types " << lht << ", "
        << rht;
  } else if (binop.op == Operator::EQ &&
             ((!binop.left->is_literal && binop.right->is_literal) ||
              (binop.left->is_literal && !binop.right->is_literal))) {
    auto *lit = binop.left->is_literal ? binop.left : binop.right;
    auto *str = lit == binop.left ? binop.right : binop.left;
    auto lit_len = bpftrace_.get_string_literal(lit).size();
    auto str_len = str->type.GetSize();
    if (lit_len > str_len) {
      LOG(WARNING, binop.left->loc + binop.loc + binop.right->loc, out_)
          << "The literal is longer than the variable string (size=" << str_len
          << "), condition will always be false";
    }
  }
}

void SemanticAnalyser::visit(Unop &unop)
{
  if (unop.op == Operator::INCREMENT || unop.op == Operator::DECREMENT) {
    // Handle ++ and -- before visiting unop.expr, because these
    // operators should be able to work with undefined maps.
    if (!unop.expr->is_map && !unop.expr->is_variable) {
      LOG(ERROR, unop.loc, err_)
          << "The " << opstr(unop)
          << " operator must be applied to a map or variable";
    }

    if (unop.expr->is_map) {
      Map &map = static_cast<Map &>(*unop.expr);
      auto *maptype = get_map_type(map);
      if (!maptype)
        assign_map_type(map, CreateInt64());
    }
  }

  unop.expr = dereference_if_needed(unop.expr);

  auto valid_ptr_op = false;
  switch (unop.op) {
    case Operator::INCREMENT:
    case Operator::DECREMENT:
    case Operator::MUL:
      valid_ptr_op = true;
      break;
    default:;
  }

  SizedType &type = unop.expr->type;
  if (is_final_pass()) {
    // Unops are only allowed on ints (e.g. ~$x), dereference only on pointers
    // and context (we allow args->field for backwards compatibility)
    // References are not allowed, instead they get turned into pointers by the
    // `dereference_if_needed()`.
    if (!type.IsIntegerTy() &&
        !((type.IsPtrTy() || type.IsCtxAccess()) && valid_ptr_op)) {
      LOG(ERROR, unop.loc, err_)
          << "The " << opstr(unop)
          << " operator can not be used on expressions of type '" << type
          << "'";
    }
  }

  if (unop.op == Operator::MUL) {
    if (type.IsPtrTy()) {
      unop.type = SizedType(*type.GetPointeeTy());
      if (type.IsCtxAccess())
        unop.type.MarkCtxAccess();
      unop.type.is_internal = type.is_internal;
      unop.type.SetAS(type.GetAS());

      // BPF verifier cannot track BTF information for double pointers
      if (!unop.type.IsPtrTy())
        unop.type.is_btftype = type.is_btftype;
    } else if (type.IsRecordTy()) {
      // We allow dereferencing "args" with no effect (for backwards compat)
      if (type.IsCtxAccess())
        unop.type = type;
      else {
        LOG(ERROR, unop.loc, err_)
            << "Can not dereference struct/union of type '" << type.GetName()
            << "'. It is not a pointer.";
      }
    } else if (type.IsIntTy()) {
      unop.type = CreateUInt64();
    }
  } else if (unop.op == Operator::LNOT) {
    // CreateUInt() abort if a size is invalid, so check the size here
    if (!(type.GetSize() == 0 || type.GetSize() == 1 || type.GetSize() == 2 ||
          type.GetSize() == 4 || type.GetSize() == 8)) {
      LOG(ERROR, unop.loc, err_)
          << "The " << opstr(unop)
          << " operator can not be used on expressions of type '" << type
          << "'";
    } else {
      unop.type = CreateUInt(8 * type.GetSize());
    }
  } else if (type.IsPtrTy() && valid_ptr_op) {
    unop.type = unop.expr->type;
  } else {
    unop.type = CreateInteger(64, type.IsSigned());
  }
}

void SemanticAnalyser::visit(Ternary &ternary)
{
  ternary.cond = dereference_if_needed(ternary.cond);
  ternary.left = dereference_if_needed(ternary.left);
  ternary.right = dereference_if_needed(ternary.right);

  const Type &cond = ternary.cond->type.GetTy();
  const auto &lhs = ternary.left->type;
  const auto &rhs = ternary.right->type;

  if (!lhs.IsSameType(rhs)) {
    if (is_final_pass()) {
      LOG(ERROR, ternary.loc, err_)
          << "Ternary operator must return the same type: "
          << "have '" << lhs << "' and '" << rhs << "'";
    }
    // This assignment is just temporary to prevent errors
    // before the final pass
    ternary.type = lhs;
    return;
  }

  if (ternary.left->type.IsStack() &&
      ternary.left->type.stack_type != ternary.right->type.stack_type) {
    // TODO: fix this for different stack types
    LOG(ERROR, ternary.loc, err_)
        << "Ternary operator must have the same stack type on the right "
           "and left sides.";
    return;
  }

  if (is_final_pass() && cond != Type::integer && cond != Type::pointer) {
    LOG(ERROR, ternary.loc, err_) << "Invalid condition in ternary: " << cond;
    return;
  }

  if (lhs.IsIntegerTy()) {
    ternary.type = CreateInteger(64, ternary.left->type.IsSigned());
  } else {
    auto lsize = ternary.left->type.GetSize();
    auto rsize = ternary.right->type.GetSize();
    if (lhs.IsTupleTy()) {
      ternary.type = create_merged_tuple(ternary.right->type,
                                         ternary.left->type);
    } else {
      ternary.type = lsize > rsize ? ternary.left->type : ternary.right->type;
    }
  }
}

void SemanticAnalyser::visit(If &if_node)
{
  if_node.cond = dereference_if_needed(if_node.cond);

  if (is_final_pass()) {
    const Type &cond = if_node.cond->type.GetTy();
    if (cond != Type::integer && cond != Type::pointer)
      LOG(ERROR, if_node.loc, err_) << "Invalid condition in if(): " << cond;
  }

  visit(if_node.if_block);
  visit(if_node.else_block);
}

void SemanticAnalyser::visit(Unroll &unroll)
{
  unroll.expr = dereference_if_needed(unroll.expr);

  auto unroll_value = bpftrace_.get_int_literal(unroll.expr);
  if (!unroll_value.has_value()) {
    LOG(ERROR, unroll.loc, err_) << "invalid unroll value";
    return;
  }

  unroll.var = *unroll_value;

  if (unroll.var > 100) {
    LOG(ERROR, unroll.loc, err_) << "unroll maximum value is 100";
  } else if (unroll.var < 1) {
    LOG(ERROR, unroll.loc, err_) << "unroll minimum value is 1";
  }

  visit(unroll.block);
}

void SemanticAnalyser::visit(Jump &jump)
{
  switch (jump.ident) {
    case JumpType::RETURN:
      if (jump.return_value) {
        jump.return_value = dereference_if_needed(jump.return_value);
      }
      if (auto subprog = dynamic_cast<Subprog *>(top_level_node_)) {
        if ((subprog->return_type.IsVoidTy() !=
             (jump.return_value == nullptr)) ||
            (jump.return_value &&
             jump.return_value->type != subprog->return_type)) {
          LOG(ERROR, jump.loc, err_)
              << "Function " << subprog->name() << " is of type "
              << subprog->return_type << ", cannot return "
              << (jump.return_value ? jump.return_value->type : CreateVoid());
        }
      }
      break;
    case JumpType::BREAK:
    case JumpType::CONTINUE:
      if (!in_loop())
        LOG(ERROR, jump.loc, err_) << opstr(jump) << " used outside of a loop";
      break;
    default:
      LOG(ERROR, jump.loc, err_) << "Unknown jump: '" << opstr(jump) << "'";
  }
}

void SemanticAnalyser::visit(While &while_block)
{
  while_block.cond = dereference_if_needed(while_block.cond);

  loop_depth_++;
  visit(while_block.block);
  loop_depth_--;
}

void SemanticAnalyser::visit(For &f)
{
  if (!bpftrace_.feature_->has_helper_for_each_map_elem()) {
    LOG(ERROR, f.loc, err_)
        << "Missing required kernel feature: for_each_map_elem";
  }

  // For-loops are implemented using the bpf_for_each_map_elem helper function,
  // which requires them to be rewritten into a callback style.
  //
  // Pseudo code for the transformation we apply:
  //
  // Before:
  //     PROBE {
  //       @map[0] = 1;
  //       for ($kv : @map) {
  //         [LOOP BODY]
  //       }
  //     }
  //
  // After:
  //     PROBE {
  //       @map[0] = 1;
  //       bpf_for_each_map_elem(@map, &map_for_each_cb, 0, 0);
  //     }
  //     long map_for_each_cb(bpf_map *map,
  //                          const void *key,
  //                          void *value,
  //                          void *ctx) {
  //       $kv = ((uint64)key, (uint64)value);
  //       [LOOP BODY]
  //     }
  //
  //
  // To allow variables to be shared between the loop callback and the main
  // program, some extra steps are taken:
  //
  // 1. Determine which variables need to be shared with the loop callback
  // 2. Pack pointers to them into a context struct
  // 3. Pass pointer to the context struct to the callback function
  // 4. In the callback, override the shared variables so that they read and
  //    write through the context pointers instead of directly from their
  //    original addresses
  //
  // Example transformation with context:
  //
  // Before:
  //     PROBE {
  //       $str = "hello";
  //       $not_shared = 2;
  //       $len = 0;
  //       @map[11, 12] = "c";
  //       for ($kv : @map) {
  //         print($str);
  //         $len++;
  //       }
  //       print($len);
  //       print($not_shared);
  //     }
  //
  // After:
  //     struct ctx_t {
  //       string *str;
  //       uint64 *len;
  //     };
  //     PROBE {
  //       $str = "hello";
  //       $not_shared = 2;
  //       $len = 0;
  //       @map[11, 12] = "c";
  //
  //       ctx_t ctx { .str = &$str, .len = &$len };
  //       bpf_for_each_map_elem(@map, &map_for_each_cb, &ctx, 0);
  //
  //       print($len);
  //       print($not_shared);
  //     }
  //     long map_for_each_cb(bpf_map *map,
  //                          const void *key,
  //                          void *value,
  //                          void *ctx) {
  //       $kv = (((uint64, uint64))key, (string)value);
  //       $str = ((ctx_t*)ctx)->str;
  //       $len = ((ctx_t*)ctx)->len;
  //
  //       print($str);
  //       $len++;
  //     }

  // Validate decl
  const auto &decl_name = f.decl->ident;
  if (find_variable(decl_name)) {
    LOG(ERROR, f.decl->loc, err_)
        << "Loop declaration shadows existing variable: " + decl_name;
  }

  // Validate expr
  if (!f.expr->is_map) {
    LOG(ERROR, f.expr->loc, err_) << "Loop expression must be a map";
    return;
  }
  Map &map = static_cast<Map &>(*f.expr);

  if (!map.type.IsMapIterableTy()) {
    LOG(ERROR, f.expr->loc, err_)
        << "Loop expression does not support type: " << map.type;
    return;
  }

  // Validate body
  // This could be relaxed in the future:
  CollectNodes<Jump> jumps(ctx_);
  jumps.visit(f.stmts);
  for (const Jump &n : jumps.nodes()) {
    LOG(ERROR, n.loc, err_)
        << "'" << opstr(n) << "' statement is not allowed in a for-loop";
  }

  map.skip_key_validation = true;
  visit(map);

  if (has_error())
    return;

  // Collect a list of unique variables which are referenced in the loop's body
  // and declared before the loop. These will be passed into the loop callback
  // function as the context parameter.
  std::unordered_set<std::string> found_vars;
  // Only do this on the first pass because variables declared later
  // in a script will get added to the outer scope, which these do not
  // reference e.g.
  // BEGIN { @a[1] = 1; for ($kv : @a) { $x = 2; } let $x; }
  if (is_first_pass()) {
    for (auto *stmt : f.stmts) {
      // We save these for potential use at the end of this function in
      // subsequent passes in case the map we're iterating over isn't ready
      // yet and still needs additional passes to resolve its key/value types
      // e.g. BEGIN { $x = 1; for ($kv : @a) { print(($x)); } @a[1] = 1; }
      //
      // This is especially tricky because we need to visit all statements
      // inside the for loop to get the types of the referenced variables but
      // only after we have the map's key/value type so we can also check
      // the usages of the created $kv tuple variable.
      auto [iter, _] = for_vars_referenced_.try_emplace(&f, ctx_);
      auto &collector = iter->second;
      collector.visit(stmt, [this, &found_vars](const auto &var) {
        if (found_vars.find(var.ident) != found_vars.end())
          return false;

        if (find_variable(var.ident)) {
          found_vars.insert(var.ident);
          return true;
        }
        return false;
      });
    }
  }

  // Create type for the loop's decl
  // Iterating over a map provides a tuple: (map_key, map_val)
  auto *mapkey = get_map_key_type(map);
  auto *mapval = get_map_type(map);

  if (!mapval)
    return;

  if (!mapkey || mapkey->IsNoneTy()) {
    if (is_final_pass()) {
      LOG(ERROR, map.loc, err_)
          << "Maps used as for-loop expressions must have keys to iterate over";
    }
    return;
  }

  f.decl->type = CreateTuple(bpftrace_.structs.AddTuple({ *mapkey, *mapval }));

  scope_stack_.push_back(&f);

  variables_[scope_stack_.back()][decl_name] = { .type = f.decl->type,
                                                 .can_resize = true,
                                                 .was_assigned = true };

  loop_depth_++;
  accept_statements(f.stmts);
  loop_depth_--;

  scope_stack_.pop_back();

  // Currently, we do not pass BPF context to the callback so disable builtins
  // which require ctx access.
  CollectNodes<Builtin> builtins(ctx_);
  builtins.visit(f.stmts);
  for (const Builtin &builtin : builtins.nodes()) {
    if (builtin.type.IsCtxAccess() || builtin.is_argx() ||
        builtin.ident == "retval") {
      LOG(ERROR, builtin.loc, err_)
          << "'" << builtin.ident << "' builtin is not allowed in a for-loop";
    }
  }

  // Finally, create the context tuple now that all variables inside the loop
  // have been visited.
  std::vector<SizedType> ctx_types;
  std::vector<std::string_view> ctx_idents;
  auto [iter, _] = for_vars_referenced_.try_emplace(&f, ctx_);
  auto &collector = iter->second;
  for (const Variable &var : collector.nodes()) {
    ctx_types.push_back(CreatePointer(var.type, AddrSpace::bpf));
    ctx_idents.push_back(var.ident);
  }
  f.ctx_type = CreateRecord(
      "", bpftrace_.structs.AddAnonymousStruct(ctx_types, ctx_idents));
}

void SemanticAnalyser::visit(FieldAccess &acc)
{
  // A field access must have a field XOR index
  assert((acc.field.size() > 0) != (acc.index >= 0));

  acc.expr = dereference_if_needed(acc.expr);

  SizedType &type = acc.expr->type;

  if (type.IsPtrTy()) {
    LOG(ERROR, acc.loc, err_)
        << "Can not access field '" << acc.field << "' on type '" << type
        << "'. Try dereferencing it first, or using '->'";
    return;
  }

  if (!type.IsRecordTy() && !type.IsTupleTy()) {
    if (is_final_pass()) {
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

  if (type.is_funcarg) {
    auto probe = get_probe(acc.loc);
    if (probe == nullptr)
      return;
    auto arg = bpftrace_.structs.GetProbeArg(*probe, acc.field);
    if (arg) {
      // Only set acc.type if it's not already set. [1]
      // Overwriting the type once set could override the conversion
      // from Reference to Pointer done by dereference_if_needed.
      if (acc.type.IsNoneTy())
        acc.type = arg->type;
      acc.type.SetAS(acc.expr->type.GetAS());

      if (is_final_pass()) {
        if (acc.type.IsNoneTy())
          LOG(ERROR, acc.loc, err_) << acc.field << " has unsupported type";

        ProbeType probetype = single_provider_type(probe);
        if (probetype == ProbeType::fentry || probetype == ProbeType::fexit) {
          acc.type.is_btftype = true;
        }
      }
    } else {
      LOG(ERROR, acc.loc, err_)
          << "Can't find function parameter " << acc.field;
    }
    return;
  }

  if (type.IsTupleTy()) {
    if (acc.index < 0) {
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

  if (!bpftrace_.structs.Has(type.GetName())) {
    LOG(ERROR, acc.loc, err_)
        << "Unknown struct/union: '" << type.GetName() << "'";
    return;
  }

  std::map<std::string, std::weak_ptr<const Struct>> structs;

  if (type.is_tparg) {
    auto probe = get_probe(acc.loc);
    if (probe == nullptr)
      return;

    for (AttachPoint *attach_point : probe->attach_points) {
      if (probetype(attach_point->provider) != ProbeType::tracepoint) {
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
  } else {
    structs[type.GetName()] = type.GetStruct();
  }

  for (auto it : structs) {
    std::string cast_type = it.first;
    const auto record = it.second.lock();
    if (!record->HasField(acc.field)) {
      LOG(ERROR, acc.loc, err_)
          << "Struct/union of type '" << cast_type << "' does not contain "
          << "a field named '" << acc.field << "'";
    } else {
      const auto &field = record->GetField(acc.field);

      if (field.type.IsPtrTy()) {
        const auto &tags = field.type.GetBtfTypeTags();
        // Currently only "rcu" is safe. "percpu", for example, requires special
        // unwrapping with `bpf_per_cpu_ptr` which is not yet supported.
        static const std::string_view allowed_tag = "rcu";
        for (const auto &tag : tags) {
          if (tag != allowed_tag) {
            LOG(ERROR, acc.loc, err_)
                << "Attempting to access pointer field '" << acc.field
                << "' with unsupported tag attribute: " << tag;
          }
        }
      }

      // Only set acc.type if it's not already set. See explanation [1].
      if (acc.type.IsNoneTy())
        acc.type = field.type;

      if (acc.expr->type.IsCtxAccess() &&
          (acc.type.IsArrayTy() || acc.type.IsRecordTy())) {
        // e.g., ((struct bpf_perf_event_data*)ctx)->regs.ax
        acc.type.MarkCtxAccess();
      }
      acc.type.is_internal = type.is_internal;
      acc.type.is_btftype = type.is_btftype;
      acc.type.SetAS(acc.expr->type.GetAS());

      // The kernel uses the first 8 bytes to store `struct pt_regs`. Any
      // access to the first 8 bytes results in verifier error.
      if (type.is_tparg && field.offset < 8)
        LOG(ERROR, acc.loc, err_)
            << "BPF does not support accessing common tracepoint fields";
    }
  }
}

// We can't hint for unsigned types. It is a syntax error,
// because the word "unsigned" is not allowed in a type name.
static std::unordered_map<std::string_view, std::string_view>
    KNOWN_TYPE_ALIASES{
      { "char", "int8" },   /* { "unsigned char", "uint8" }, */
      { "short", "int16" }, /* { "unsigned short", "uint16" }, */
      { "int", "int32" },   /* { "unsigned int", "uint32" }, */
      { "long", "int64" },  /* { "unsigned long", "uint64" }, */
    };

void SemanticAnalyser::visit(Cast &cast)
{
  cast.expr = dereference_if_needed(cast.expr);

  // cast type is synthesised in parser, if it is a struct, it needs resolving
  resolve_struct_type(cast.type, cast.loc);

  auto rhs = cast.expr->type;
  if (rhs.IsRecordTy()) {
    LOG(ERROR, cast.loc, err_)
        << "Cannot cast from struct type \"" << cast.expr->type << "\"";
  } else if (rhs.IsNoneTy()) {
    LOG(ERROR, cast.loc, err_)
        << "Cannot cast from \"" << cast.expr->type << "\" type";
  }

  if (!cast.type.IsIntTy() && !cast.type.IsPtrTy() &&
      !(cast.type.IsPtrTy() && !cast.type.GetElementTy()->IsIntTy() &&
        !cast.type.GetElementTy()->IsRecordTy()) &&
      // we support casting integers to int arrays
      !(cast.type.IsArrayTy() && cast.type.GetElementTy()->IsIntTy())) {
    LOG(ERROR, cast.loc, err_) << "Cannot cast to \"" << cast.type << "\"";
    if (auto it = KNOWN_TYPE_ALIASES.find(cast.type.GetName());
        it != KNOWN_TYPE_ALIASES.end()) {
      LOG(HINT, cast.loc, err_) << "Did you mean \"" << it->second << "\"?";
    }
  }

  if (cast.type.IsArrayTy()) {
    if (cast.type.GetElementTy()->IsBoolTy()) {
      LOG(ERROR, cast.loc, err_) << "Bit arrays are not supported";
      return;
    }

    if (cast.type.GetNumElements() == 0) {
      if (cast.type.GetElementTy()->GetSize() == 0)
        LOG(ERROR, cast.loc, err_) << "Could not determine size of the array";
      else {
        if (rhs.GetSize() % cast.type.GetElementTy()->GetSize() != 0) {
          LOG(ERROR, cast.loc, err_)
              << "Cannot determine array size: the element size is "
                 "incompatible with the cast integer size";
        }

        // cast to unsized array (e.g. int8[]), determine size from RHS
        auto num_elems = rhs.GetSize() / cast.type.GetElementTy()->GetSize();
        cast.type = CreateArray(num_elems, *cast.type.GetElementTy());
      }
    }

    if (rhs.IsIntTy())
      cast.type.is_internal = true;
  }

  if (cast.type.IsEnumTy()) {
    if (bpftrace_.enum_defs_.count(cast.type.GetName()) == 0) {
      LOG(ERROR, cast.loc, err_) << "Unknown enum: " << cast.type.GetName();
    } else {
      if (rhs.IsIntTy() && cast.expr->is_literal) {
        auto integer = static_cast<Integer *>(cast.expr);

        if (bpftrace_.enum_defs_[cast.type.GetName()].count(integer->n) == 0) {
          LOG(ERROR, cast.expr->loc, err_)
              << "Enum: " << cast.type.GetName()
              << " doesn't contain a variant value of " << integer->n;
        }
      }
    }
  }

  if ((cast.type.IsIntTy() && !rhs.IsIntTy() && !rhs.IsPtrTy() &&
       !rhs.IsCtxAccess() && !rhs.IsArrayTy() && !rhs.IsCastableMapTy()) ||
      // casting from/to int arrays must respect the size
      (cast.type.IsArrayTy() &&
       (!rhs.IsIntTy() || cast.type.GetSize() != rhs.GetSize())) ||
      (rhs.IsArrayTy() &&
       (!cast.type.IsIntTy() || cast.type.GetSize() != rhs.GetSize()))) {
    LOG(ERROR, cast.loc, err_)
        << "Cannot cast from \"" << rhs << "\" to \"" << cast.type << "\"";
  }

  if (cast.expr->type.IsCtxAccess() && !cast.type.IsIntTy())
    cast.type.MarkCtxAccess();
  cast.type.SetAS(cast.expr->type.GetAS());
  // case : BEGIN { @foo = (struct Foo)0; }
  // case : profile:hz:99 $task = (struct task_struct *)curtask.
  if (cast.type.GetAS() == AddrSpace::none) {
    if (auto probe = dynamic_cast<Probe *>(top_level_node_)) {
      ProbeType type = single_provider_type(probe);
      cast.type.SetAS(find_addrspace(type));
    } else {
      // Assume kernel space for data in subprogs
      cast.type.SetAS(AddrSpace::kernel);
    }
  }
}

void SemanticAnalyser::visit(Tuple &tuple)
{
  std::vector<SizedType> elements;
  for (auto &elem : tuple.elems) {
    elem = dereference_if_needed(elem);

    // If elem type is none that means that the tuple contains some
    // invalid cast (e.g., (0, (aaa)0)). In this case, skip the tuple
    // creation. Cast already emits the error.
    if (elem->type.IsNoneTy() || elem->type.GetSize() == 0) {
      return;
    } else if (elem->type.IsMultiOutputMapTy()) {
      LOG(ERROR, elem->loc, err_)
          << "Map type " << elem->type << " cannot exist inside a tuple.";
    }
    elements.emplace_back(elem->type);
  }

  tuple.type = CreateTuple(bpftrace_.structs.AddTuple(elements));
}

void SemanticAnalyser::visit(ExprStatement &expr)
{
  expr.expr = dereference_if_needed(expr.expr);
}

static const std::unordered_map<Type, std::string_view> AGGREGATE_HINTS{
  { Type::count_t, "count()" },
  { Type::sum_t, "sum(retval)" },
  { Type::min_t, "min(retval)" },
  { Type::max_t, "max(retval)" },
  { Type::avg_t, "avg(retval)" },
  { Type::hist_t, "hist(retval)" },
  { Type::lhist_t, "lhist(rand %10, 0, 10, 1)" },
  { Type::stats_t, "stats(arg2)" },
};

void SemanticAnalyser::visit(AssignMapStatement &assignment)
{
  assignment.map->is_read = false;
  visit(assignment.map);
  assignment.expr = dereference_if_needed(assignment.expr);

  const auto *map_type_before = get_map_type(*assignment.map);
  if (!is_valid_assignment(assignment.map, assignment.expr)) {
    const auto &type = assignment.expr->type;
    auto hint = AGGREGATE_HINTS.find(type.GetTy());
    if (hint == AGGREGATE_HINTS.end())
      LOG(BUG) << "Missing assignment hint";

    LOG(ERROR, assignment.loc, err_)
        << "Map value '" << type
        << "' cannot be assigned from one map to another. "
           "The function that returns this type must be called directly e.g. `"
        << assignment.map->ident << " = " << hint->second << ";`.";

    if (auto *expr_map = dynamic_cast<const Map *>(assignment.expr)) {
      if (type.IsCastableMapTy()) {
        LOG(HINT, err_)
            << "Add a cast to integer if you want the value of the aggregate, "
               "e.g. `"
            << assignment.map->ident << " = (int64)" << expr_map->ident
            << ";`.";
      }
    }
  }

  // Add an implicit cast when copying the value of an aggregate map to an
  // existing map of int. Enables the following: `@x = 1; @y = count(); @x = @y`
  const bool map_contains_int = map_type_before && map_type_before->IsIntTy();
  const bool expr_is_map_with_castable_agg =
      assignment.expr->is_map && assignment.expr->type.IsCastableMapTy();
  if (map_contains_int && expr_is_map_with_castable_agg) {
    assignment.expr = ctx_.make_node<Cast>(*map_type_before,
                                           assignment.expr,
                                           assignment.expr->loc);
  }

  assign_map_type(*assignment.map, assignment.expr->type);

  const auto &map_ident = assignment.map->ident;
  const auto &type = assignment.expr->type;

  if (type.IsRecordTy() && map_val_[map_ident].IsRecordTy()) {
    std::string ty = assignment.expr->type.GetName();
    std::string stored_ty = map_val_[map_ident].GetName();
    if (!stored_ty.empty() && stored_ty != ty) {
      LOG(ERROR, assignment.loc, err_)
          << "Type mismatch for " << map_ident << ": "
          << "trying to assign value of type '" << ty
          << "' when map already contains a value of type '" << stored_ty
          << "'";
    } else {
      map_val_[map_ident] = assignment.expr->type;
      map_val_[map_ident].is_internal = true;
    }
  } else if (type.IsStringTy()) {
    auto map_size = map_val_[map_ident].GetSize();
    auto expr_size = assignment.expr->type.GetSize();
    if (map_size < expr_size) {
      LOG(WARNING, assignment.loc, out_)
          << "String size mismatch: " << map_size << " < " << expr_size
          << ". The value may be truncated.";
    }
  } else if (type.IsBufferTy()) {
    auto map_size = map_val_[map_ident].GetSize();
    auto expr_size = assignment.expr->type.GetSize();
    if (map_size != expr_size) {
      std::stringstream buf;
      buf << "Buffer size mismatch: " << map_size << " != " << expr_size << ".";
      if (map_size < expr_size) {
        buf << " The value may be truncated.";
        LOG(WARNING, assignment.loc, out_) << buf.str();
      } else {
        // bpf_map_update_elem() expects map_size-length value
        LOG(ERROR, assignment.loc, err_) << buf.str();
      }
    }
  } else if (type.IsCtxAccess()) {
    // bpf_map_update_elem() only accepts a pointer to a element in the stack
    LOG(ERROR, assignment.loc, err_) << "context cannot be assigned to a map";
  } else if (type.IsTupleTy()) {
    // Early passes may not have been able to deduce the full types of tuple
    // elements yet. So wait until final pass.
    if (is_final_pass()) {
      const auto &map_type = map_val_[map_ident];
      const auto &expr_type = assignment.expr->type;
      if (!expr_type.FitsInto(map_type)) {
        LOG(ERROR, assignment.loc, err_) << "Tuple type mismatch: " << map_type
                                         << " != " << expr_type << ".";
      }
    }
  } else if (type.IsArrayTy()) {
    const auto &map_type = map_val_[map_ident];
    const auto &expr_type = assignment.expr->type;
    if (map_type == expr_type) {
      map_val_[map_ident].is_internal = true;
    } else {
      LOG(ERROR, assignment.loc, err_)
          << "Array type mismatch: " << map_type << " != " << expr_type << ".";
    }
  }
}

void SemanticAnalyser::visit(AssignVarStatement &assignment)
{
  assignment.expr = dereference_if_needed(assignment.expr);
  if (assignment.var_decl_stmt) {
    visit(assignment.var_decl_stmt);
  }

  if (!is_valid_assignment(assignment.var, assignment.expr)) {
    LOG(ERROR, assignment.loc, err_)
        << "Map value '" << assignment.expr->type
        << "' cannot be assigned to a scratch variable.";
  }

  const bool expr_is_map_with_castable_agg =
      assignment.expr->is_map && assignment.expr->type.IsCastableMapTy();
  if (expr_is_map_with_castable_agg) {
    assignment.expr = ctx_.make_node<Cast>(CreateInt64(),
                                           assignment.expr,
                                           assignment.expr->loc);
  }

  Node *var_scope = nullptr;
  const auto &var_ident = assignment.var->ident;
  const auto &assignTy = assignment.expr->type;

  if (auto *scope = find_variable_scope(var_ident)) {
    auto &foundVar = variables_[scope][var_ident];
    auto &storedTy = foundVar.type;
    bool type_mismatch_error = false;
    if (storedTy.IsNoneTy()) {
      storedTy = assignTy;
    } else if (!storedTy.IsSameType(assignTy)) {
      if (!assignTy.IsNoneTy() || is_final_pass()) {
        type_mismatch_error = true;
      } else {
        pass_tracker_.inc_num_unresolved();
      }
    } else if (assignTy.IsStringTy()) {
      if (foundVar.can_resize) {
        update_string_size(storedTy, assignTy);
      } else if (!assignTy.FitsInto(storedTy)) {
        type_mismatch_error = true;
      }
    } else if (storedTy.IsIntegerTy()) {
      if (assignment.expr->is_literal) {
        auto integer = static_cast<Integer *>(assignment.expr);
        if (!storedTy.IsEqual(assignTy)) {
          int64_t value = integer->n;
          bool can_fit = false;
          if (integer->is_negative) {
            if (!storedTy.IsSigned()) {
              type_mismatch_error = true;
            } else {
              auto min_max = getIntTypeRange(storedTy);
              can_fit = value >= min_max.first;
            }
          } else {
            if (!storedTy.IsSigned()) {
              auto min_max = getUIntTypeRange(storedTy);
              can_fit = static_cast<uint64_t>(value) <= min_max.second;
            } else {
              // Casting to a uint64 here because the assign 'value'
              // might be larger than the max signed int64 e.g.
              // `$x = -1; $x = 10223372036854775807;`
              auto min_max = getIntTypeRange(storedTy);
              can_fit = static_cast<uint64_t>(value) <=
                        static_cast<uint64_t>(min_max.second);
            }
          }
          if (can_fit) {
            Expression *cast = ctx_.make_node<Cast>(
                CreateInteger(storedTy.GetSize() * 8, storedTy.IsSigned()),
                assignment.expr,
                assignment.loc);
            assignment.expr = dereference_if_needed(cast);
          } else if (!type_mismatch_error) {
            LOG(ERROR, assignment.loc, err_)
                << "Type mismatch for " << var_ident << ": "
                << "trying to assign value '"
                << (integer->is_negative ? integer->n
                                         : static_cast<uint64_t>(integer->n))
                << "' which does not fit into the variable of type '"
                << storedTy << "'";
          }
        }
      } else if (storedTy.IsSigned() != assignTy.IsSigned()) {
        type_mismatch_error = true;
      } else {
        if (!assignTy.FitsInto(storedTy)) {
          LOG(ERROR, assignment.loc, err_)
              << "Integer size mismatch. Assignment type '" << assignTy
              << "' is larger than the variable type '" << storedTy << "'.";
        }
      }
    } else if (assignTy.IsBufferTy()) {
      auto var_size = storedTy.GetSize();
      auto expr_size = assignTy.GetSize();
      if (var_size != expr_size) {
        LOG(WARNING, assignment.loc, out_)
            << "Buffer size mismatch: " << var_size << " != " << expr_size
            << (var_size < expr_size ? ". The value may be truncated."
                                     : ". The value may contain garbage.");
      }
    } else if (assignTy.IsTupleTy()) {
      update_string_size(storedTy, assignTy);
      // Early passes may not have been able to deduce the full types of tuple
      // elements yet. So wait until final pass.
      if (is_final_pass()) {
        if (!assignTy.FitsInto(storedTy)) {
          type_mismatch_error = true;
        }
      }
    }
    if (type_mismatch_error) {
      auto err_segment = foundVar.was_assigned
                             ? "when variable already contains a value of type"
                             : "when variable already has a type";
      LOG(ERROR, assignment.loc, err_)
          << "Type mismatch for " << var_ident << ": "
          << "trying to assign value of type '" << assignTy << "' "
          << err_segment << " '" << storedTy << "'";
    } else {
      if (!foundVar.was_assigned) {
        // The assign type is possibly more complete than the stored type,
        // which could come from a variable declaration. The assign type may
        // resolve builtins like `curtask` which also specifies the address
        // space.
        foundVar.type = assignTy;
        foundVar.was_assigned = true;
      }
      var_scope = scope;
    }
  }

  if (var_scope == nullptr) {
    variables_[scope_stack_.back()].insert(
        { var_ident,
          { .type = assignTy, .can_resize = true, .was_assigned = true } });
    var_scope = scope_stack_.back();
  }

  const auto &storedTy = variables_[var_scope][var_ident].type;
  assignment.var->type = storedTy;

  if (is_final_pass()) {
    if (storedTy.IsNoneTy())
      LOG(ERROR, assignment.expr->loc, err_)
          << "Invalid expression for assignment: " << storedTy;
  }
}

void SemanticAnalyser::visit(AssignConfigVarStatement &assignment)
{
  assignment.expr = dereference_if_needed(assignment.expr);
}

void SemanticAnalyser::visit(VarDeclStatement &decl)
{
  const std::string &var_ident = decl.var->ident;

  if (!IsValidVarDeclType(decl.var->type)) {
    LOG(ERROR, decl.loc, err_)
        << "Invalid variable declaration type: " << decl.var->type;
  }

  // Only checking on the first pass for cases like this:
  // `BEGIN { if (1) { let $x; } else { let $x; } let $x; }`
  // Notice how the last `let $x` is defined in the outer scope;
  // this means on subsequent passes the first two `let $x` statements
  // would be considered variable shadowing, when in fact, because of order,
  // there is no ambiguity in terms of future assignment and use.
  if (is_first_pass()) {
    for (auto scope : scope_stack_) {
      // This should be the first time we're seeing this variable
      if (auto decl_search = variable_decls_[scope].find(var_ident);
          decl_search != variable_decls_[scope].end()) {
        if (decl_search->second != decl.loc) {
          LOG(ERROR, decl.loc, err_)
              << "Variable " << var_ident
              << " was already declared. Variable shadowing is not allowed.";
          LOG(ERROR, decl_search->second, err_) << "Initial declaration";
        }
      }
    }
  }

  if (is_first_pass() || is_final_pass()) {
    if (auto *scope = find_variable_scope(var_ident)) {
      auto &foundVar = variables_[scope][var_ident];
      // Checking the first pass only for cases like this:
      // `BEGIN { if (1) { let $x; } $x = 2; }`
      // Again, this is legal and there is no ambiguity but `$x = 2` gets
      // placed in the outer scope so subsequent passes would consider
      // this a use before declaration error (below)
      if (!variable_decls_[scope].contains(var_ident) && is_first_pass()) {
        LOG(ERROR, decl.loc, err_)
            << "Variable declarations need to occur before variable usage or "
               "assignment. Variable: "
            << var_ident;
      } else if (is_final_pass()) {
        // Update the declaration type if it was either not set e.g. `let $a;`
        // or the type is ambiguous or resizable e.g. `let $a: string;`
        decl.var->type = foundVar.type;
      }

      if (is_final_pass() && !foundVar.was_assigned) {
        LOG(WARNING, decl.loc, out_)
            << "Variable " << var_ident << " never assigned to.";
      }

      return;
    }
  }

  bool can_resize = !decl.set_type || decl.var->type.GetSize() == 0;

  variables_[scope_stack_.back()].insert({ var_ident,
                                           { .type = decl.var->type,
                                             .can_resize = can_resize,
                                             .was_assigned = false } });
  variable_decls_[scope_stack_.back()].insert({ var_ident, decl.loc });
}

void SemanticAnalyser::visit(Predicate &pred)
{
  pred.expr = dereference_if_needed(pred.expr);
  if (is_final_pass()) {
    SizedType &ty = pred.expr->type;
    if (!ty.IsIntTy() && !ty.IsPtrTy()) {
      LOG(ERROR, pred.loc, err_)
          << "Invalid type for predicate: " << pred.expr->type.GetTy();
    }
  }
}

void SemanticAnalyser::visit(AttachPoint &ap)
{
  if (ap.provider == "kprobe" || ap.provider == "kretprobe") {
    if (ap.func == "")
      LOG(ERROR, ap.loc, err_) << "kprobes should be attached to a function";
    if (is_final_pass()) {
      // Warn if user tries to attach to a non-traceable function
      if (bpftrace_.config_.get(ConfigKeyMissingProbes::default_) !=
              ConfigMissingProbes::ignore &&
          !has_wildcard(ap.func) && !bpftrace_.is_traceable_func(ap.func)) {
        LOG(WARNING, ap.loc, out_)
            << ap.func
            << " is not traceable (either non-existing, inlined, or marked as "
               "\"notrace\"); attaching to it will likely fail";
      }
    }
  } else if (ap.provider == "uprobe" || ap.provider == "uretprobe") {
    if (ap.target == "")
      LOG(ERROR, ap.loc, err_) << ap.provider << " should have a target";
    if (ap.func == "" && ap.address == 0)
      LOG(ERROR, ap.loc, err_)
          << ap.provider << " should be attached to a function and/or address";
    if (ap.lang != "" && !is_supported_lang(ap.lang))
      LOG(ERROR, ap.loc, err_) << "unsupported language type: " << ap.lang;

    if (ap.provider == "uretprobe" && ap.func_offset != 0)
      LOG(ERROR, ap.loc, err_)
          << "uretprobes can not be attached to a function offset";

    std::vector<std::string> paths;
    if (ap.target == "*") {
      if (bpftrace_.pid() > 0)
        paths = get_mapped_paths_for_pid(bpftrace_.pid());
      else
        paths = get_mapped_paths_for_running_pids();
    } else {
      paths = resolve_binary_path(ap.target, bpftrace_.pid());
    }
    switch (paths.size()) {
      case 0:
        LOG(ERROR, ap.loc, err_) << "uprobe target file '" << ap.target
                                 << "' does not exist or is not executable";
        break;
      case 1:
        // Replace the glob at this stage only if this is *not* a wildcard,
        // otherwise we rely on the probe matcher. This is not going through
        // any interfaces that can be properly mocked.
        if (ap.target.find("*") == std::string::npos)
          ap.target = paths.front();
        break;
      default:
        // If we are doing a PATH lookup (ie not glob), we follow shell
        // behavior and take the first match.
        // Otherwise we keep the target with glob, it will be expanded later
        if (ap.target.find("*") == std::string::npos) {
          LOG(WARNING, ap.loc, out_)
              << "attaching to uprobe target file '" << paths.front()
              << "' but matched " << std::to_string(paths.size())
              << " binaries";
          ap.target = paths.front();
        }
    }
  } else if (ap.provider == "usdt") {
    bpftrace_.has_usdt_ = true;
    if (ap.func == "")
      LOG(ERROR, ap.loc, err_)
          << "usdt probe must have a target function or wildcard";

    if (ap.target != "" && !(bpftrace_.pid() > 0 && has_wildcard(ap.target))) {
      auto paths = resolve_binary_path(ap.target, bpftrace_.pid());
      switch (paths.size()) {
        case 0:
          LOG(ERROR, ap.loc, err_) << "usdt target file '" << ap.target
                                   << "' does not exist or is not executable";
          break;
        case 1:
          // See uprobe, above.
          if (ap.target.find("*") == std::string::npos)
            ap.target = paths.front();
          break;
        default:
          // See uprobe, above.
          if (ap.target.find("*") == std::string::npos) {
            LOG(WARNING, ap.loc, out_)
                << "attaching to usdt target file '" << paths.front()
                << "' but matched " << std::to_string(paths.size())
                << " binaries";
            ap.target = paths.front();
          }
      }
    }

    if (bpftrace_.pid() > 0) {
      USDTHelper::probes_for_pid(bpftrace_.pid());
    } else if (ap.target == "*") {
      USDTHelper::probes_for_all_pids();
    } else if (ap.target != "") {
      for (auto &path : resolve_binary_path(ap.target))
        USDTHelper::probes_for_path(path);
    } else {
      LOG(ERROR, ap.loc, err_)
          << "usdt probe must specify at least path or pid to probe. To target "
             "all paths/pids set the path to '*'.";
    }
  } else if (ap.provider == "tracepoint") {
    if (ap.target == "" || ap.func == "")
      LOG(ERROR, ap.loc, err_) << "tracepoint probe must have a target";
  } else if (ap.provider == "rawtracepoint") {
    if (ap.target != "")
      LOG(ERROR, ap.loc, err_) << "rawtracepoint should not have a target";
    if (ap.func == "")
      LOG(ERROR, ap.loc, err_)
          << "rawtracepoint should be attached to a function";
  } else if (ap.provider == "profile") {
    if (ap.target == "")
      LOG(ERROR, ap.loc, err_) << "profile probe must have unit of time";
    else if (!listing_) {
      if (TIME_UNITS.find(ap.target) == TIME_UNITS.end())
        LOG(ERROR, ap.loc, err_)
            << ap.target << " is not an accepted unit of time";
      if (ap.func != "")
        LOG(ERROR, ap.loc, err_)
            << "profile probe must have an integer frequency";
      else if (ap.freq <= 0)
        LOG(ERROR, ap.loc, err_)
            << "profile frequency should be a positive integer";
    }
  } else if (ap.provider == "interval") {
    if (ap.target == "")
      LOG(ERROR, ap.loc, err_) << "interval probe must have unit of time";
    else if (!listing_) {
      if (TIME_UNITS.find(ap.target) == TIME_UNITS.end())
        LOG(ERROR, ap.loc, err_)
            << ap.target << " is not an accepted unit of time";
      if (ap.func != "")
        LOG(ERROR, ap.loc, err_)
            << "interval probe must have an integer frequency";
      else if (ap.freq <= 0)
        LOG(ERROR, ap.loc, err_)
            << "interval frequency should be a positive integer";
    }
  } else if (ap.provider == "software") {
    if (ap.target == "")
      LOG(ERROR, ap.loc, err_)
          << "software probe must have a software event name";
    else {
      if (!has_wildcard(ap.target) && !ap.ignore_invalid) {
        bool found = false;
        for (auto &probeListItem : SW_PROBE_LIST) {
          if (ap.target == probeListItem.path ||
              (!probeListItem.alias.empty() &&
               ap.target == probeListItem.alias)) {
            found = true;
            break;
          }
        }
        if (!found)
          LOG(ERROR, ap.loc, err_) << ap.target << " is not a software probe";
      } else if (!listing_) {
        LOG(ERROR, ap.loc, err_)
            << "wildcards are not allowed for hardware probe type";
      }
    }
    if (ap.func != "")
      LOG(ERROR, ap.loc, err_)
          << "software probe can only have an integer count";
    else if (ap.freq < 0)
      LOG(ERROR, ap.loc, err_) << "software count should be a positive integer";
  } else if (ap.provider == "watchpoint" || ap.provider == "asyncwatchpoint") {
    if (ap.func.size()) {
      if (bpftrace_.pid() <= 0 && !has_child_)
        LOG(ERROR, ap.loc, err_) << "-p PID or -c CMD required for watchpoint";

      if (ap.address > static_cast<uint64_t>(arch::max_arg()))
        LOG(ERROR, ap.loc, err_)
            << arch::name() << " doesn't support arg" << ap.address;
    } else if (ap.provider == "asyncwatchpoint")
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
    for (size_t i = 1; i < ap.mode.size(); ++i) {
      if (ap.mode[i - 1] == ap.mode[i])
        LOG(ERROR, ap.loc, err_) << "watchpoint modes may not be duplicated";
    }
    const auto invalid_modes = arch::invalid_watchpoint_modes();
    if (std::any_of(invalid_modes.cbegin(),
                    invalid_modes.cend(),
                    [&](const auto &mode) { return mode == ap.mode; }))
      LOG(ERROR, ap.loc, err_) << "invalid watchpoint mode: " << ap.mode;
  } else if (ap.provider == "hardware") {
    if (ap.target == "")
      LOG(ERROR, ap.loc, err_)
          << "hardware probe must have a hardware event name";
    else {
      if (!has_wildcard(ap.target) && !ap.ignore_invalid) {
        bool found = false;
        for (auto &probeListItem : HW_PROBE_LIST) {
          if (ap.target == probeListItem.path ||
              (!probeListItem.alias.empty() &&
               ap.target == probeListItem.alias)) {
            found = true;
            break;
          }
        }
        if (!found)
          LOG(ERROR, ap.loc, err_) << ap.target + " is not a hardware probe";
      } else if (!listing_) {
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
  } else if (ap.provider == "BEGIN" || ap.provider == "END") {
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
  } else if (ap.provider == "self") {
    if (ap.target == "signal") {
      if (SIGNALS.find(ap.func) == SIGNALS.end())
        LOG(ERROR, ap.loc, err_) << ap.func << " is not a supported signal";
      return;
    }
    LOG(ERROR, ap.loc, err_) << ap.target << " is not a supported trigger";
  } else if (ap.provider == "fentry" || ap.provider == "fexit") {
    if (!bpftrace_.feature_->has_fentry()) {
      LOG(ERROR, ap.loc, err_)
          << "fentry/fexit not available for your kernel version.";
      return;
    }

    if (ap.func == "")
      LOG(ERROR, ap.loc, err_) << "fentry/fexit should specify a function";
  } else if (ap.provider == "iter") {
    if (!listing_ && bpftrace_.btf_->get_all_iters().count(ap.func) <= 0) {
      LOG(ERROR, ap.loc, err_)
          << "iter " << ap.func << " not available for your kernel version.";
    }

    if (ap.func == "")
      LOG(ERROR, ap.loc, err_) << "iter should specify a iterator's name";
  } else {
    LOG(ERROR, ap.loc, err_) << "Invalid provider: '" << ap.provider << "'";
  }
}

void SemanticAnalyser::visit(Block &block)
{
  scope_stack_.push_back(&block);
  accept_statements(block.stmts);
  scope_stack_.pop_back();
}

void SemanticAnalyser::visit(Probe &probe)
{
  auto aps = probe.attach_points.size();
  top_level_node_ = &probe;

  for (AttachPoint *ap : probe.attach_points) {
    if (!listing_ && aps > 1 && ap->provider == "iter") {
      LOG(ERROR, ap->loc, err_) << "Only single iter attach point is allowed.";
      return;
    }
    visit(ap);
  }
  visit(probe.pred);
  visit(probe.block);
}

void SemanticAnalyser::visit(Config &config)
{
  accept_statements(config.stmts);
}

void SemanticAnalyser::visit(Subprog &subprog)
{
  scope_stack_.push_back(&subprog);
  top_level_node_ = &subprog;
  for (SubprogArg *arg : subprog.args) {
    variables_[scope_stack_.back()].insert(
        { arg->name(),
          { .type = arg->type, .can_resize = true, .was_assigned = true } });
  }
  Visitor<SemanticAnalyser>::visit(subprog);
  scope_stack_.pop_back();
}

int SemanticAnalyser::analyse()
{
  std::string errors;

  int last_num_unresolved = 0;
  // Multiple passes to handle variables being used before they are defined
  while (true) {
    pass_tracker_.reset_num_unresolved();

    visit(ctx_.root);

    errors = err_.str();
    if (!errors.empty()) {
      out_ << errors;
      return pass_tracker_.get_num_passes();
    }

    if (is_final_pass()) {
      return 0;
    }

    int num_unresolved = pass_tracker_.get_num_unresolved();

    if (num_unresolved > 0 &&
        (last_num_unresolved == 0 || num_unresolved < last_num_unresolved)) {
      // If we're making progress, keep making passes
      last_num_unresolved = num_unresolved;
    } else {
      pass_tracker_.mark_final_pass();
    }

    pass_tracker_.inc_num_passes();
  }
}

inline bool SemanticAnalyser::is_final_pass() const
{
  return pass_tracker_.is_final_pass();
}

bool SemanticAnalyser::is_first_pass() const
{
  return pass_tracker_.get_num_passes() == 1;
}

bool SemanticAnalyser::check_assignment(const Call &call,
                                        bool want_map,
                                        bool want_var,
                                        bool want_map_key)
{
  if (want_map && want_var && want_map_key) {
    if (!call.map && !call.var && !call.key_for_map) {
      LOG(ERROR, call.loc, err_) << call.func
                                 << "() should be assigned to a map or a "
                                    "variable, or be used as a map key";
      return false;
    }
  } else if (want_map && want_var) {
    if (!call.map && !call.var) {
      LOG(ERROR, call.loc, err_)
          << call.func << "() should be assigned to a map or a variable";
      return false;
    }
  } else if (want_map && want_map_key) {
    if (!call.map && !call.key_for_map) {
      LOG(ERROR, call.loc, err_)
          << call.func
          << "() should be assigned to a map or be used as a map key";
      return false;
    }
  } else if (want_var && want_map_key) {
    if (!call.var && !call.key_for_map) {
      LOG(ERROR, call.loc, err_)
          << call.func
          << "() should be assigned to a variable or be used as a map key";
      return false;
    }
  } else if (want_map) {
    if (!call.map) {
      LOG(ERROR, call.loc, err_)
          << call.func << "() should be directly assigned to a map";
      return false;
    }
  } else if (want_var) {
    if (!call.var) {
      LOG(ERROR, call.loc, err_)
          << call.func << "() should be assigned to a variable";
      return false;
    }
  } else if (want_map_key) {
    if (!call.key_for_map) {
      LOG(ERROR, call.loc, err_)
          << call.func << "() should be used as a map key";
      return false;
    }
  } else {
    if (call.map || call.var || call.key_for_map) {
      LOG(ERROR, call.loc, err_)
          << call.func
          << "() should not be used in an assignment or as a map key";
      return false;
    }
  }
  return true;
}

// Checks the number of arguments passed to a function is correct.
bool SemanticAnalyser::check_nargs(const Call &call, size_t expected_nargs)
{
  std::stringstream err;
  auto nargs = call.vargs.size();

  if (nargs != expected_nargs) {
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

// Checks the number of arguments passed to a function is within a specified
// range.
bool SemanticAnalyser::check_varargs(const Call &call,
                                     size_t min_nargs,
                                     size_t max_nargs)
{
  std::stringstream err;
  auto nargs = call.vargs.size();

  if (nargs < min_nargs) {
    if (min_nargs == 1)
      err << call.func << "() requires at least one argument";
    else
      err << call.func << "() requires at least " << min_nargs << " arguments";

    err << " (" << nargs << " provided)";
    LOG(ERROR, call.loc, err_) << err.str();
    return false;
  } else if (nargs > max_nargs) {
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

// Checks an argument passed to a function is of the correct type.
//
// This function does not check that the function has the correct number of
// arguments. Either check_nargs() or check_varargs() should be called first to
// validate this.
bool SemanticAnalyser::check_arg(const Call &call,
                                 Type type,
                                 int arg_num,
                                 bool want_literal,
                                 bool fail)
{
  auto &arg = *call.vargs.at(arg_num);
  if (want_literal && (!arg.is_literal || arg.type.GetTy() != type)) {
    if (fail) {
      LOG(ERROR, call.loc, err_)
          << call.func << "() expects a " << type << " literal ("
          << arg.type.GetTy() << " provided)";
      if (type == Type::string) {
        // If the call requires a string literal and a positional parameter is
        // given, tell user to use str()
        auto *pos_param = dynamic_cast<PositionalParameter *>(&arg);
        if (pos_param)
          LOG(ERROR) << "Use str($" << pos_param->n << ") to treat $"
                     << pos_param->n << " as a string";
      }
    }
    return false;
  } else if (is_final_pass() && arg.type.GetTy() != type) {
    if (fail) {
      LOG(ERROR, call.loc, err_)
          << call.func << "() only supports " << type << " arguments ("
          << arg.type.GetTy() << " provided)";
    }
    return false;
  }
  return true;
}

bool SemanticAnalyser::check_symbol(const Call &call,
                                    int arg_num __attribute__((unused)))
{
  auto arg = bpftrace_.get_string_literal(call.vargs.at(0));

  std::string re = "^[a-zA-Z0-9./_-]+$";
  bool is_valid = std::regex_match(arg, std::regex(re));
  if (!is_valid) {
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

  if (func == "reg") {
    switch (type) {
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
      case ProbeType::special:
      case ProbeType::tracepoint:
      case ProbeType::fentry:
      case ProbeType::fexit:
      case ProbeType::iter:
      case ProbeType::rawtracepoint:
        return false;
    }
  } else if (func == "uaddr") {
    switch (type) {
      case ProbeType::usdt:
      case ProbeType::uretprobe:
      case ProbeType::uprobe:
        return true;
      case ProbeType::invalid:
      case ProbeType::special:
      case ProbeType::kprobe:
      case ProbeType::kretprobe:
      case ProbeType::tracepoint:
      case ProbeType::profile:
      case ProbeType::interval:
      case ProbeType::software:
      case ProbeType::hardware:
      case ProbeType::watchpoint:
      case ProbeType::asyncwatchpoint:
      case ProbeType::fentry:
      case ProbeType::fexit:
      case ProbeType::iter:
      case ProbeType::rawtracepoint:
        return false;
    }
  } else if (func == "signal") {
    switch (type) {
      case ProbeType::kprobe:
      case ProbeType::kretprobe:
      case ProbeType::uprobe:
      case ProbeType::uretprobe:
      case ProbeType::usdt:
      case ProbeType::tracepoint:
      case ProbeType::profile:
      case ProbeType::fentry:
      case ProbeType::fexit:
      case ProbeType::rawtracepoint:
        return true;
      case ProbeType::invalid:
      case ProbeType::special:
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

SizedType *SemanticAnalyser::get_map_type(const Map &map)
{
  const std::string &map_ident = map.ident;
  auto search = map_val_.find(map_ident);
  if (search == map_val_.end())
    return nullptr;
  return &search->second;
}

SizedType *SemanticAnalyser::get_map_key_type(const Map &map)
{
  if (auto it = map_key_.find(map.ident); it != map_key_.end()) {
    return &it->second;
  }
  return nullptr;
}

// assign_map_type
//
//   Semantic analysis for assigning a value of the provided type
//   to the given map.
void SemanticAnalyser::assign_map_type(const Map &map, const SizedType &type)
{
  const std::string &map_ident = map.ident;

  if (type.IsRecordTy() && type.is_tparg) {
    LOG(ERROR, map.loc, err_)
        << "Storing tracepoint args in maps is not supported";
  }

  auto *maptype = get_map_type(map);
  if (maptype) {
    if (maptype->IsNoneTy()) {
      pass_tracker_.inc_num_unresolved();
      if (is_final_pass())
        LOG(ERROR, map.loc, err_) << "Undefined map: " + map_ident;
      else
        *maptype = type;
    } else if (maptype->GetTy() != type.GetTy()) {
      LOG(ERROR, map.loc, err_)
          << "Type mismatch for " << map_ident << ": "
          << "trying to assign value of type '" << type
          << "' when map already contains a value of type '" << *maptype << "'";
    }

    if (maptype->IsStringTy() || maptype->IsTupleTy())
      update_string_size(*maptype, type);
  } else {
    // This map hasn't been seen before
    map_val_.insert({ map_ident, type });
    if (map_val_[map_ident].IsIntTy()) {
      // Store all integer values as 64-bit in maps, so that there will
      // be space for any integer to be assigned to the map later
      map_val_[map_ident].SetSize(8);
    }
  }
}

void SemanticAnalyser::accept_statements(StatementList &stmts)
{
  for (size_t i = 0; i < stmts.size(); i++) {
    visit(stmts.at(i));
    auto stmt = stmts.at(i);

    if (is_final_pass()) {
      auto *jump = dynamic_cast<Jump *>(stmt);
      if (jump && i < (stmts.size() - 1)) {
        LOG(WARNING, jump->loc, out_)
            << "All code after a '" << opstr(*jump) << "' is unreachable.";
      }
    }
  }
}

SizedType SemanticAnalyser::create_key_type(const SizedType &expr_type,
                                            const location &loc)
{
  SizedType new_key_type = expr_type;
  if (expr_type.IsTupleTy()) {
    std::vector<SizedType> elements;
    for (const auto &field : expr_type.GetFields()) {
      SizedType keytype = create_key_type(field.type, loc);
      elements.push_back(std::move(keytype));
    }
    new_key_type = CreateTuple(bpftrace_.structs.AddTuple(elements));
  } else if (expr_type.IsIntegerTy()) {
    // Store all integer values as 64-bit in map keys, so that there will
    // be space for any integer in the map key later
    // This should have a better solution.
    new_key_type.SetSign(true);
    new_key_type.SetIntBitWidth(64);
  }

  validate_map_key(new_key_type, loc);
  return new_key_type;
}

void SemanticAnalyser::update_current_key(SizedType &current_key_type,
                                          const SizedType &new_key_type)
{
  if (current_key_type.IsSameType(new_key_type) &&
      (current_key_type.IsStringTy() || current_key_type.IsTupleTy())) {
    update_string_size(current_key_type, new_key_type);
  }
}

void SemanticAnalyser::validate_new_key(const SizedType &current_key_type,
                                        const SizedType &new_key_type,
                                        const std::string &map_ident,
                                        const location &loc)
{
  // Map keys can get resized/updated across multiple passes
  // wait till the end to log an error if there is a key mismatch.
  if (!is_final_pass()) {
    return;
  }

  bool valid = true;
  if (current_key_type.IsSameType(new_key_type)) {
    if (current_key_type.IsTupleTy() || current_key_type.IsIntegerTy() ||
        current_key_type.IsStringTy()) {
      // This should always be true as map integer keys default to 64 bits
      // and strings get resized (this happens recursively into tuples as well)
      // but keep this here just in case we add larger ints and need to
      // update the map int logic
      if (!new_key_type.FitsInto(current_key_type)) {
        valid = false;
      }
    } else if (!current_key_type.IsEqual(new_key_type)) {
      valid = false;
    }
  } else {
    valid = false;
  }

  if (valid) {
    return;
  }

  if (current_key_type.IsNoneTy()) {
    LOG(ERROR, loc, err_) << "Argument mismatch for " << map_ident << ": "
                          << "trying to access with arguments: '"
                          << new_key_type << "' when map expects no arguments";
  } else {
    LOG(ERROR, loc, err_) << "Argument mismatch for " << map_ident << ": "
                          << "trying to access with arguments: '"
                          << new_key_type << "' when map expects arguments: '"
                          << current_key_type << "'";
  }
}

bool SemanticAnalyser::update_string_size(SizedType &type,
                                          const SizedType &new_type)
{
  if (type.IsStringTy() && new_type.IsStringTy() &&
      type.GetSize() != new_type.GetSize()) {
    type.SetSize(std::max(type.GetSize(), new_type.GetSize()));
    return true;
  }

  if (type.IsTupleTy() && new_type.IsTupleTy() &&
      type.GetFieldCount() == new_type.GetFieldCount()) {
    bool updated = false;
    std::vector<SizedType> new_elems;
    for (ssize_t i = 0; i < type.GetFieldCount(); i++) {
      if (update_string_size(type.GetField(i).type, new_type.GetField(i).type))
        updated = true;
      new_elems.push_back(type.GetField(i).type);
    }
    if (updated) {
      type = CreateTuple(bpftrace_.structs.AddTuple(new_elems));
    }
    return updated;
  }

  return false;
}

SizedType SemanticAnalyser::create_merged_tuple(const SizedType &left,
                                                const SizedType &right)
{
  assert(left.IsTupleTy() && right.IsTupleTy() &&
         (left.GetFieldCount() == right.GetFieldCount()));

  std::vector<SizedType> new_elems;
  for (ssize_t i = 0; i < left.GetFieldCount(); i++) {
    const auto &leftTy = left.GetField(i).type;
    const auto &rightTy = right.GetField(i).type;

    assert(leftTy.GetTy() == rightTy.GetTy());
    if (leftTy.IsTupleTy()) {
      new_elems.push_back(create_merged_tuple(leftTy, rightTy));
    } else {
      new_elems.push_back(leftTy.GetSize() > rightTy.GetSize() ? leftTy
                                                               : rightTy);
    }
  }
  return CreateTuple(bpftrace_.structs.AddTuple(new_elems));
}

void SemanticAnalyser::resolve_struct_type(SizedType &type, const location &loc)
{
  const SizedType *inner_type = &type;
  int pointer_level = 0;
  while (inner_type->IsPtrTy()) {
    inner_type = inner_type->GetPointeeTy();
    pointer_level++;
  }
  if (inner_type->IsRecordTy() && inner_type->GetStruct().expired()) {
    auto struct_type = bpftrace_.structs.Lookup(inner_type->GetName());
    if (struct_type.expired())
      LOG(ERROR, loc, err_) << "Cannot resolve unknown type \""
                            << inner_type->GetName() << "\"\n";
    type = CreateRecord(inner_type->GetName(), struct_type);
    while (pointer_level > 0) {
      type = CreatePointer(type);
      pointer_level--;
    }
  }
}

bool SemanticAnalyser::has_error() const
{
  const auto &errors = err_.str();
  return !errors.empty();
}

Pass CreateSemanticPass()
{
  auto fn = [](PassContext &ctx) {
    auto semantics = SemanticAnalyser(ctx.ast_ctx, ctx.b, !ctx.b.cmd_.empty());
    int err = semantics.analyse();
    if (err)
      return PassResult::Error("Semantic", err);
    return PassResult::Success();
  };

  return Pass("Semantic", fn);
};

Expression *SemanticAnalyser::dereference_if_needed(Expression *expr)
{
  visit(expr);
  if (expr->type.IsRefTy()) {
    expr->type.IntoPointer();
    const SizedType &ptr_type = expr->type;
    Expression *ptr_expr = expr;

    Unop *deref_expr = ctx_.make_node<Unop>(
        Operator::MUL, ptr_expr, false, ptr_expr->loc);
    deref_expr->type = *ptr_type.GetPointeeTy();
    deref_expr->type.is_internal = ptr_type.is_internal;
    deref_expr->type.SetAS(ptr_type.GetAS());
    if (ptr_type.IsCtxAccess())
      deref_expr->type.MarkCtxAccess();
    return deref_expr;
  }
  return expr;
}

variable *SemanticAnalyser::find_variable(const std::string &var_ident)
{
  if (auto *scope = find_variable_scope(var_ident)) {
    return &variables_[scope][var_ident];
  }
  return nullptr;
}

Node *SemanticAnalyser::find_variable_scope(const std::string &var_ident)
{
  for (auto scope : scope_stack_) {
    if (auto search_val = variables_[scope].find(var_ident);
        search_val != variables_[scope].end()) {
      return scope;
    }
  }
  return nullptr;
}

} // namespace bpftrace::ast
