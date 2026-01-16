#include <optional>

#include "arch/arch.h"
#include "ast/passes/builtins.h"
#include "ast/signal_bt.h"
#include "ast/visitor.h"
#include "bpffeature.h"
#include "bpftrace.h"
#include "collect_nodes.h"
#include "log.h"
#include "util/paths.h"

namespace bpftrace::ast {

namespace {

class Builtins : public Visitor<Builtins, std::optional<Expression>> {
public:
  explicit Builtins(ASTContext &ast, BPFtrace &bpftrace, bool has_child = true)
      : ast_(ast), bpftrace_(bpftrace), has_child_(has_child) {};

  using Visitor<Builtins, std::optional<Expression>>::visit;
  std::optional<Expression> visit(Builtin &builtin);
  std::optional<Expression> visit(Call &call);
  std::optional<Expression> visit(Identifier &identifier);
  std::optional<Expression> visit(Expression &expression);
  std::optional<Expression> visit(For &f);
  std::optional<Expression> visit(Probe &probe);
  std::optional<Expression> check(const std::string &ident, Node &node);

  Probe *get_probe(Node &node, std::string name);

private:
  ASTContext &ast_;
  BPFtrace &bpftrace_;
  bool has_child_ = false;
  Node *top_level_node_ = nullptr;
};

} // namespace

Probe *Builtins::get_probe(Node &node, std::string name)
{
  auto *probe = dynamic_cast<Probe *>(top_level_node_);
  if (probe == nullptr) {
    // Attempting to use probe-specific feature in non-probe context
    if (name.empty()) {
      node.addError() << "Feature not supported outside probe";
    } else {
      node.addError() << "Builtin " << name << " not supported outside probe";
    }
  }

  return probe;
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
    if (auto *probe = dynamic_cast<Probe *>(top_level_node_)) {
      return ast_.make_node<String>(node.loc,
                                    probe->attach_points.empty()
                                        ? "none"
                                        : probe->attach_points.front()->name());
    }
  }
  if (ident == "__builtin_probetype") {
    if (auto *probe = dynamic_cast<Probe *>(top_level_node_)) {
      return ast_.make_node<String>(
          node.loc,
          probe->attach_points.empty()
              ? "none"
              : probetypeName(
                    probetype(probe->attach_points.front()->provider)));
    }
  }
  if (ident == "__builtin_elf_is_exe" || ident == "__builtin_elf_ino") {
    auto *probe = dynamic_cast<Probe *>(top_level_node_);
    if (!probe) {
      return std::nullopt;
    }
    ProbeType type = probetype(probe->attach_points.front()->provider);
    // Only for uprobe,uretprobe,USDT.
    if (type != ProbeType::uprobe && type != ProbeType::uretprobe &&
        type != ProbeType::usdt) {
      LOG(BUG) << "The " << ident << " can not be used with '"
               << probe->attach_points.front()->provider << "' probes";
    }
    if (ident == "__builtin_elf_is_exe") {
      return ast_.make_node<Boolean>(
          node.loc, util::is_exe(probe->attach_points.front()->target));
    } else {
      return ast_.make_node<Integer>(
          node.loc, util::file_ino(probe->attach_points.front()->target));
    }
  }
  return std::nullopt;
}

std::optional<Expression> Builtins::visit(Call &call)
{
  Visitor<Builtins, std::optional<Expression>>::visit(call);
  if (call.func == "__builtin_signal_num") {
    if (call.vargs.size() != 1) {
      call.addError() << call.func << " expects 1 argument";
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
    if (call.vargs.size() != 1) {
      call.addError() << call.func << " expects 1 argument";
    } else {
      if (auto *kfunc = call.vargs.at(0).as<String>()) {
        return ast_.make_node<Boolean>(
            kfunc->loc, bpftrace_.feature_->has_kfunc(kfunc->value));
      }
    }
  } else if (call.func == "__builtin_kfunc_allowed") {
    if (call.vargs.size() != 1) {
      call.addError() << call.func << " expects 1 argument";
    } else {
      auto *probe = dynamic_cast<Probe *>(top_level_node_);
      if (!probe) {
        LOG(BUG) << "Inner error: can't get probe for " << call.func;
        return std::nullopt;
      }
      ProbeType type = probetype(probe->attach_points.front()->provider);
      bpf_prog_type prog_type = progtype(type);
      if (auto *kfunc = call.vargs.at(0).as<String>()) {
        return ast_.make_node<Boolean>(
            kfunc->loc,
            bpftrace_.feature_->kfunc_allowed(kfunc->value.c_str(), prog_type));
      }
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
  if (builtin.ident == "ctx") {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return std::nullopt;
    ProbeType pt = probe->get_probetype();
    bpf_prog_type bt = progtype(pt);
    bool has_error = false;
    switch (bt) {
      case BPF_PROG_TYPE_KPROBE:
      case BPF_PROG_TYPE_PERF_EVENT:
        break;
      case BPF_PROG_TYPE_TRACEPOINT:
        builtin.addError() << "Use args instead of ctx in tracepoint";
        break;
      case BPF_PROG_TYPE_TRACING:
        if (pt != ProbeType::iter) {
          has_error = true;
        }
        break;
      default:
        has_error = true;
        break;
    }

    if (has_error) {
      builtin.addError() << "The " << builtin.ident
                         << " builtin can not be used with '"
                         << probe->attach_points[0]->provider << "' probes";
    }
  } else if (builtin.ident == "__builtin_func") {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return std::nullopt;
    ProbeType type = probe->get_probetype();
    if (type == ProbeType::kprobe || type == ProbeType::uprobe) {
      // OK we don't use BPF_FUNC_get_func_ip helper
    } else if (type == ProbeType::kretprobe || type == ProbeType::uretprobe ||
               type == ProbeType::fentry || type == ProbeType::fexit) {
      if (!bpftrace_.feature_->has_helper_get_func_ip()) {
        builtin.addError()
            << "BPF_FUNC_get_func_ip not available for your kernel version. "
               "Consider using the 'probe' builtin instead.";
      }
    } else {
      builtin.addError() << "The func builtin can not be used with '"
                         << probe->attach_points[0]->provider << "' probes";
    }
  } else if (builtin.ident == "__builtin_retval") {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return std::nullopt;
    ProbeType type = probe->get_probetype();
    if (type != ProbeType::kretprobe && type != ProbeType::uretprobe &&
        type != ProbeType::fentry && type != ProbeType::fexit) {
      builtin.addError()
          << "The retval builtin can only be used with 'kretprobe' and "
          << "'uretprobe' and 'fentry' probes"
          << (type == ProbeType::tracepoint ? " (try to use args.ret instead)"
                                            : "");
    }
  } else if (builtin.is_argx()) {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return std::nullopt;
    int arg_num = atoi(builtin.ident.substr(3).c_str());
    ProbeType type = probe->get_probetype();
    if (type != ProbeType::kprobe && type != ProbeType::uprobe &&
        type != ProbeType::usdt && type != ProbeType::rawtracepoint) {
      // N.B. this works for rawtracepoints but it's discouraged
      builtin.addError() << "The " << builtin.ident
                         << " builtin can only be used with "
                         << "'kprobes', 'uprobes' and 'usdt' probes";
    }
    // argx in USDT probes doesn't need to check against arch::max_arg()
    if (type != ProbeType::usdt &&
        static_cast<size_t>(arg_num) >= arch::Host::arguments().size()) {
      builtin.addError() << arch::Host::Machine << " doesn't support "
                         << builtin.ident;
    }

  } else if (builtin.ident == "__builtin_usermode") {
    if (arch::Host::Machine != arch::Machine::X86_64) {
      builtin.addError() << "'usermode' builtin is only supported on x86_64";
    }
  } else if (builtin.ident == "__builtin_cpid") {
    if (!has_child_) {
      builtin.addError() << "cpid cannot be used without child command";
    }
  } else if (builtin.ident == "args") {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return std::nullopt;
    ProbeType type = probe->get_probetype();

    if (type == ProbeType::fentry || type == ProbeType::fexit ||
        type == ProbeType::uprobe || type == ProbeType::rawtracepoint ||
        type == ProbeType::tracepoint) {
      if ((type == ProbeType::fentry || type == ProbeType::fexit) &&
          probe->attach_points[0]->target == "bpf") {
        builtin.addError() << "The args builtin cannot be used for "
                              "'fentry/fexit:bpf' probes";
      }
    } else {
      builtin.addError()
          << "The args builtin can only be used with "
             "tracepoint, rawtracepoint, fentry/fexit, and uprobe probes ("
          << type << " used here)";
    }
  }

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

std::optional<Expression> Builtins::visit(For &f)
{
  // Currently, we do not pass BPF context to the callback so disable builtins
  // which require ctx access.
  CollectNodes<Builtin> builtins;
  builtins.visit(f.block);
  for (const Builtin &builtin : builtins.nodes()) {
    if (builtin.is_argx() || builtin.ident == "__builtin_retval") {
      builtin.addError() << "'" << builtin.ident
                         << "' builtin is not allowed in a for-loop";
    }
  }

  return std::nullopt;
}

std::optional<Expression> Builtins::visit(Probe &probe)
{
  top_level_node_ = &probe;
  return Visitor<Builtins, std::optional<Expression>>::visit(probe);
}

Pass CreateBuiltinsPass()
{
  auto fn = [&](ASTContext &ast, BPFtrace &bpftrace) {
    Builtins builtins(ast,
                      bpftrace,
                      !bpftrace.cmd_.empty() || bpftrace.child_ != nullptr);
    builtins.visit(ast.root);
  };

  return Pass::create("Builtins", fn);
};

} // namespace bpftrace::ast
