#include <optional>

#include "arch/arch.h"
#include "ast/passes/builtins.h"
#include "ast/signal_bt.h"
#include "ast/visitor.h"
#include "bpffeature.h"
#include "bpftrace.h"
#include "log.h"
#include "util/paths.h"

namespace bpftrace::ast {

namespace {

class Builtins : public Visitor<Builtins, std::optional<Expression>> {
public:
  explicit Builtins(ASTContext &ast, BPFtrace &bpftrace)
      : ast_(ast), bpftrace_(bpftrace) {};

  using Visitor<Builtins, std::optional<Expression>>::visit;
  std::optional<Expression> visit(Builtin &builtin);
  std::optional<Expression> visit(Call &call);
  std::optional<Expression> visit(Identifier &identifier);
  std::optional<Expression> visit(Expression &expression);
  std::optional<Expression> visit(Probe &probe);
  std::optional<Expression> visit(Subprog &subprog);
  std::optional<Expression> check(const std::string &ident, Node &node);

private:
  ASTContext &ast_;
  BPFtrace &bpftrace_;
  std::optional<ProbeType> probe_type_;
  std::optional<bpf_prog_type> prog_type_;
  std::optional<std::string> probe_target_;
};

} // namespace

static std::string probe_type_name(ProbeType t)
{
  switch (t) {
    case ProbeType::invalid:
      return "invalid";
    case ProbeType::special:
      return "special";
    case ProbeType::benchmark:
      return "benchmark";
    case ProbeType::kprobe:
      return "kprobe";
    case ProbeType::kretprobe:
      return "kretprobe";
    case ProbeType::uprobe:
      return "uprobe";
    case ProbeType::uretprobe:
      return "uretprobe";
    case ProbeType::usdt:
      return "usdt";
    case ProbeType::tracepoint:
      return "tracepoint";
    case ProbeType::profile:
      return "profile";
    case ProbeType::interval:
      return "interval";
    case ProbeType::software:
      return "software";
    case ProbeType::hardware:
      return "hardware";
    case ProbeType::watchpoint:
      return "watchpoint";
    case ProbeType::asyncwatchpoint:
      return "asyncwatchpoint";
    case ProbeType::fentry:
      return "fentry";
    case ProbeType::fexit:
      return "fexit";
    case ProbeType::iter:
      return "iter";
    case ProbeType::rawtracepoint:
      return "rawtracepoint";
    default:
      return "unknown";
  }
}

static std::string prog_type_name(bpf_prog_type t)
{
  switch (t) {
    case BPF_PROG_TYPE_UNSPEC:
      return "unspec";
    case BPF_PROG_TYPE_SOCKET_FILTER:
      return "socket_filter";
    case BPF_PROG_TYPE_KPROBE:
      return "kprobe";
    case BPF_PROG_TYPE_SCHED_CLS:
      return "sched_cls";
    case BPF_PROG_TYPE_SCHED_ACT:
      return "sched_act";
    case BPF_PROG_TYPE_TRACEPOINT:
      return "tracepoint";
    case BPF_PROG_TYPE_XDP:
      return "xdp";
    case BPF_PROG_TYPE_PERF_EVENT:
      return "perf_event";
    case BPF_PROG_TYPE_CGROUP_SKB:
      return "cgroup_skb";
    case BPF_PROG_TYPE_CGROUP_SOCK:
      return "cgroup_sock";
    case BPF_PROG_TYPE_LWT_IN:
      return "lwt_in";
    case BPF_PROG_TYPE_LWT_OUT:
      return "lwt_out";
    case BPF_PROG_TYPE_LWT_XMIT:
      return "lwt_xmit";
    case BPF_PROG_TYPE_SOCK_OPS:
      return "sock_ops";
    case BPF_PROG_TYPE_SK_SKB:
      return "sk_skb";
    case BPF_PROG_TYPE_CGROUP_DEVICE:
      return "cgroup_device";
    case BPF_PROG_TYPE_SK_MSG:
      return "sk_msg";
    case BPF_PROG_TYPE_RAW_TRACEPOINT:
      return "raw_tracepoint";
    case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
      return "cgroup_sock_addr";
    case BPF_PROG_TYPE_LWT_SEG6LOCAL:
      return "lwt_seg6local";
    case BPF_PROG_TYPE_LIRC_MODE2:
      return "lirc_mode2";
    case BPF_PROG_TYPE_SK_REUSEPORT:
      return "sk_reuseport";
    case BPF_PROG_TYPE_FLOW_DISSECTOR:
      return "flow_dissector";
    case BPF_PROG_TYPE_CGROUP_SYSCTL:
      return "cgroup_sysctl";
    case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE:
      return "raw_tracepoint_writable";
    case BPF_PROG_TYPE_CGROUP_SOCKOPT:
      return "cgroup_sockopt";
    case BPF_PROG_TYPE_TRACING:
      return "tracing";
    case BPF_PROG_TYPE_STRUCT_OPS:
      return "struct_ops";
    case BPF_PROG_TYPE_EXT:
      return "ext";
    case BPF_PROG_TYPE_LSM:
      return "lsm";
    case BPF_PROG_TYPE_SK_LOOKUP:
      return "sk_lookup";
    case BPF_PROG_TYPE_SYSCALL:
      return "syscall";
    case BPF_PROG_TYPE_NETFILTER:
      return "netfilter";
    default:
      return "unknown";
  }
}

std::optional<Expression> Builtins::check(const std::string &ident, Node &node)
{
  // N.B. this pass *should* include all the compile-time builtins (probe,
  // provider, etc.) but it presently cannot due to the expansion rules. All
  // builtins should be added here once probes are fully-expanded up front.
  //
  // All of these builtins should be directly evaluated and folded and not
  // associated with any code generation. These builtins should be kept to the
  // minimum possible set to support the standard library.
  if (ident == "__builtin_arch") {
    std::stringstream ss;
    ss << bpftrace::arch::current();
    return ast_.make_node<String>(node.loc, ss.str());
  }
  if (ident == "__builtin_safe_mode") {
    return ast_.make_node<Boolean>(node.loc, bpftrace_.safe_mode_);
  }
  if (ident == "__builtin_probe") {
    if (probe_type_ && probe_target_) {
      return ast_.make_node<String>(node.loc,
                                    probe_type_name(*probe_type_) + ":" +
                                        *probe_target_);
    } else {
      node.addError() << "probe type not available";
    }
  }
  if (ident == "__builtin_probe_type") {
    if (probe_type_) {
      return ast_.make_node<String>(node.loc,
                                    probe_type_name(probe_type_.value()));
    } else {
      node.addError() << "probe type not available";
    }
  }
  if (ident == "__builtin_prog_type") {
    if (prog_type_) {
      return ast_.make_node<String>(node.loc,
                                    prog_type_name(prog_type_.value()));
    } else {
      node.addError() << "program type not available";
    }
  }
  if (ident == "__builtin_elf_is_exe" || ident == "__builtin_elf_ino") {
    if (!probe_type_) {
      return std::nullopt;
    }
    // Only for uprobe,uretprobe,USDT.
    if (*probe_type_ != ProbeType::uprobe &&
        *probe_type_ != ProbeType::uretprobe &&
        *probe_type_ != ProbeType::usdt) {
      LOG(BUG) << "The " << ident << " can not be used with '" << *probe_type_
               << "' probes";
    }
    if (ident == "__builtin_elf_is_exe") {
      return ast_.make_node<Boolean>(node.loc, util::is_exe(*probe_target_));
    } else {
      return ast_.make_node<Integer>(node.loc, util::file_ino(*probe_target_));
    }
  }
  return std::nullopt;
}

std::optional<Expression> Builtins::visit(Call &call)
{
  Visitor<Builtins, std::optional<Expression>>::visit(call);
  if (call.func == "__builtin_signal_num") {
    if (call.vargs.size() != 1) {
      call.addError() << "__builtin_signal_num expects 1 argument";
    } else {
      if (auto *str = call.vargs.at(0).as<String>()) {
        auto signal_num = signal_name_to_num(str->value);
        if (signal_num < 1) {
          call.addError() << "Invalid string for signal: " << str->value;
        }
        return ast_.make_node<Integer>(str->loc, signal_num);
      }
    }
  } else if (call.func == "__builtin_kfunc_exist") {
    if (call.vargs.size() != 1 || !call.vargs.at(0).is<String>()) {
      call.addError() << call.func << " expects 1 string literal argument";
    } else {
      auto *kfunc = call.vargs.at(0).as<String>();
      return ast_.make_node<Boolean>(
          kfunc->loc, bpftrace_.feature_->has_kfunc(kfunc->value));
    }
  } else if (call.func == "__builtin_kfunc_allowed") {
    if (call.vargs.size() != 1 || !call.vargs.at(0).is<String>()) {
      call.addError() << call.func << " expects 1 string literal argument";
    } else {
      auto *kfunc = call.vargs.at(0).as<String>();
      if (!prog_type_) {
        return ast_.make_node<Boolean>(kfunc->loc, false);
      }
      return ast_.make_node<Boolean>(
          kfunc->loc,
          bpftrace_.feature_->kfunc_allowed(kfunc->value.c_str(), *prog_type_));
    }
  } else if (call.func == "__builtin_is_literal") {
    if (call.vargs.size() != 1) {
      call.addError() << call.func << " expects 1 argument";
    } else {
      return ast_.make_node<Boolean>(call.vargs.at(0).loc(),
                                     call.vargs.at(0).is_literal());
    }
  }
  return std::nullopt;
}

std::optional<Expression> Builtins::visit(Builtin &builtin)
{
  return check(builtin.ident, builtin);
}

std::optional<Expression> Builtins::visit(Identifier &identifier)
{
  return check(identifier.ident, identifier);
}

std::optional<Expression> Builtins::visit(Expression &expression)
{
  auto replacement = visit(expression.value);
  if (replacement) {
    expression.value = replacement->value;
  }
  return std::nullopt;
}

std::optional<Expression> Builtins::visit(Probe &probe)
{
  if (!probe.attach_points.empty()) {
    auto &ap = probe.attach_points[0];
    probe_type_ = probetype(ap->provider);
    prog_type_ = progtype(probe_type_.value());
    probe_target_ = ap->target;
  } else {
    probe_type_.reset();
    prog_type_.reset();
    probe_target_.reset();
  }

  return Visitor<Builtins, std::optional<Expression>>::visit(probe);
}

std::optional<Expression> Builtins::visit(Subprog &subprog)
{
  probe_type_.reset();
  prog_type_.reset();

  return Visitor<Builtins, std::optional<Expression>>::visit(subprog);
}

Pass CreateBuiltinsPass()
{
  auto fn = [&](ASTContext &ast, BPFtrace &bpftrace) {
    Builtins builtins(ast, bpftrace);
    builtins.visit(ast.root);
  };

  return Pass::create("Builtins", fn);
};

} // namespace bpftrace::ast
