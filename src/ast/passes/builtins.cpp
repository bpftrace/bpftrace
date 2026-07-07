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
  auto *probe = dynamic_cast<Probe *>(top_level_node_);
  auto check_probe = [&]() -> bool {
    if (!probe) {
      node.addError() << ident << " can only be used inside of a probe.";
      return false;
    }
    return true;
  };

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
  } else if (ident == "__builtin_safe_mode") {
    return ast_.make_node<Boolean>(node.loc, bpftrace_.safe_mode_);
  } else if (ident == "__builtin_probe") {
    if (check_probe()) {
      return ast_.make_node<String>(node.loc,
                                    probe->attach_points.empty()
                                        ? "none"
                                        : probe->attach_points.front()->name());
    }
  } else if (ident == "__builtin_probetype") {
    if (check_probe()) {
      return ast_.make_node<String>(
          node.loc,
          probe->attach_points.empty()
              ? "none"
              : probetypeName(
                    probetype(probe->attach_points.front()->provider)));
    }
  } else if (ident == "__builtin_elf_is_exe") {
    if (check_probe()) {
      return ast_.make_node<Boolean>(
          node.loc, util::is_exe(probe->attach_points.front()->target));
    }
  } else if (ident == "__builtin_elf_ino") {
    if (check_probe()) {
      return ast_.make_node<Integer>(
          node.loc, util::file_ino(probe->attach_points.front()->target));
    }
  } else if (ident == "__builtin_config") {
    std::vector<std::pair<std::string, Expression>> args;
    auto &cfg = bpftrace_.config_;

    auto add_bool = [&](const char *key, bool val) {
      args.emplace_back(key, ast_.make_node<Boolean>(node.loc, val));
    };
    auto add_int = [&](const char *key, uint64_t val) {
      args.emplace_back(key, ast_.make_node<Integer>(node.loc, val));
    };
    auto add_str = [&](const char *key, const std::string &val) {
      args.emplace_back(key, ast_.make_node<String>(node.loc, val));
    };

    // Booleans
    add_bool("cpp_demangle", cfg->cpp_demangle);
    add_bool("lazy_symbolication", cfg->lazy_symbolication);
    add_bool("print_maps_on_exit", cfg->print_maps_on_exit);
    add_bool("use_blazesym", cfg->use_blazesym);
    add_bool("show_debug_info", cfg->show_debug_info);

    // Integers
    add_int("log_size", cfg->log_size);
    add_int("max_bpf_progs", cfg->max_bpf_progs);
    add_int("max_cat_bytes", cfg->max_cat_bytes);
    add_int("max_map_keys", cfg->max_map_keys);
    add_int("max_probes", cfg->max_probes);
    add_int("max_strlen", cfg->max_strlen);
    add_int("on_stack_limit", cfg->on_stack_limit);
    add_int("perf_rb_pages", cfg->perf_rb_pages);

    // Strings
    add_str("str_trunc_trailer", cfg->str_trunc_trailer);

    // Enums -> Strings
    auto unstable_str = [](ConfigUnstable u) {
      switch (u) {
        case ConfigUnstable::enable:
          return "enable";
        case ConfigUnstable::warn:
          return "warn";
        case ConfigUnstable::error:
          return "error";
      }
      return "error";
    };

    add_str("unstable_import_statement",
            unstable_str(cfg->unstable_import_statement));
    add_str("unstable_tseries", unstable_str(cfg->unstable_tseries));
    add_str("unstable_typeinfo", unstable_str(cfg->unstable_typeinfo));
    add_str("unstable_dw_ustack", unstable_str(cfg->unstable_dw_ustack));

    std::string missing_str;
    switch (cfg->missing_probes) {
      case ConfigMissingProbes::ignore:
        missing_str = "ignore";
        break;
      case ConfigMissingProbes::warn:
        missing_str = "warn";
        break;
      case ConfigMissingProbes::error:
        missing_str = "error";
        break;
    }

    add_str("missing_probes", missing_str);

    add_str("stack_mode", STACK_MODE_NAME_MAP.at(cfg->stack_mode));

    add_str("license", bpftrace::Config::get_license_str(cfg->license));
    return make_record(ast_, node.loc, std::move(args));
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
  } else if (builtin.is_argx()) {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return std::nullopt;
    int arg_num = atoi(builtin.ident.substr(3).c_str());
    // argx in USDT probes doesn't need to check against arch::max_arg()
    if (probe->get_probetype() != ProbeType::usdt &&
        static_cast<size_t>(arg_num) >= arch::Host::arguments().size()) {
      builtin.addError() << arch::Host::Machine << " doesn't support "
                         << builtin.ident;
    }

  } else if (builtin.ident == "__builtin_usermode") {
    if (arch::Host::Machine != arch::Machine::X86_64) {
      builtin.addError() << "'usermode' builtin is only supported on x86_64";
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

Pass CreatePreExpansionBuiltinsPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &) {
    for (auto *probe : ast.root->probes) {
      CollectNodes<Builtin> collector;
      collector.visit(*probe);
      for (const Builtin &builtin : collector.nodes()) {
        for (auto *ap : probe->attach_points) {
          ProbeType type = probetype(ap->provider);
          if (builtin.ident == "__builtin_retval") {
            if (type != ProbeType::kretprobe && type != ProbeType::uretprobe &&
                type != ProbeType::fentry && type != ProbeType::fexit) {
              builtin.addError()
                  << "The retval builtin can only be used with 'kretprobe' "
                     "and 'uretprobe' and 'fentry' probes"
                  << (type == ProbeType::tracepoint
                          ? " (try to use args.ret instead)"
                          : "");
            }
          } else if (builtin.is_argx()) {
            if (type != ProbeType::kprobe && type != ProbeType::uprobe &&
                type != ProbeType::usdt && type != ProbeType::rawtracepoint) {
              builtin.addError() << "The " << builtin.ident
                                 << " builtin can only be used with "
                                    "'kprobes', 'uprobes' and 'usdt' probes";
            }
          }
        }
      }
    }
  };

  return Pass::create("BuiltinProbeCheck", fn);
}

} // namespace bpftrace::ast
