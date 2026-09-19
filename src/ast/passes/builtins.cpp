#include <optional>

#include "arch/arch.h"
#include "ast/passes/builtins.h"
#include "ast/passes/fold_literals.h"
#include "ast/signal_bt.h"
#include "ast/visitor.h"
#include "bpffeature.h"
#include "bpftrace.h"
#include "collect_nodes.h"
#include "util/paths.h"

namespace bpftrace::ast {

namespace {

class Builtins : public Visitor<Builtins, std::optional<Expression>> {
public:
  Builtins(ASTContext &ast, BPFtrace &bpftrace) : ast_(ast), bpftrace_(bpftrace)
  {
  }

  using Visitor<Builtins, std::optional<Expression>>::visit;

  std::optional<Expression> visit(Expression &expr)
  {
    auto replacement = Visitor<Builtins, std::optional<Expression>>::visit(
        expr.value);
    if (replacement) {
      expr.value = replacement->value;
    }
    return std::nullopt;
  }

  std::optional<Expression> visit(Builtin &builtin)
  {
    return fold_builtin(builtin.ident, builtin.loc);
  }

  std::optional<Expression> visit(Identifier &identifier)
  {
    return fold_builtin(identifier.ident, identifier.loc);
  }

  std::optional<Expression> visit(Call &call)
  {
    Visitor<Builtins, std::optional<Expression>>::visit(call);
    if (call.func == "__builtin_signal_num" && call.vargs.size() == 1) {
      if (auto *str = call.vargs.at(0).as<String>()) {
        auto signal_num = signal_name_to_num(str->value);
        if (signal_num > 0) {
          return ast_.make_node<Integer>(str->loc, signal_num);
        }
      }
    } else if (call.func == "__builtin_kfunc_exist" && call.vargs.size() == 1) {
      if (auto *kfunc = call.vargs.at(0).as<String>()) {
        return ast_.make_node<Boolean>(
            kfunc->loc, bpftrace_.feature_->has_kfunc(kfunc->value));
      }
    } else if (call.func == "__builtin_kfunc_allowed" &&
               call.vargs.size() == 1) {
      if (auto *probe = current_probe(); probe != nullptr) {
        ProbeType type = probetype(probe->attach_points.front()->provider);
        bpf_prog_type prog_type = progtype(type);
        if (auto *kfunc = call.vargs.at(0).as<String>()) {
          return ast_.make_node<Boolean>(kfunc->loc,
                                         bpftrace_.feature_->kfunc_allowed(
                                             kfunc->value.c_str(), prog_type));
        }
      }
    } else if (call.func == "__builtin_is_literal" && call.vargs.size() == 1) {
      return ast_.make_node<Boolean>(call.vargs.at(0).loc(),
                                     call.vargs.at(0).is_literal());
    }

    return std::nullopt;
  }

  std::optional<Expression> visit(Probe &probe)
  {
    auto *old = top_level_node_;
    top_level_node_ = &probe;
    auto result = Visitor<Builtins, std::optional<Expression>>::visit(probe);
    top_level_node_ = old;
    return result;
  }

  std::optional<Expression> visit(Subprog &subprog)
  {
    auto *old = top_level_node_;
    top_level_node_ = &subprog;
    auto result = Visitor<Builtins, std::optional<Expression>>::visit(subprog);
    top_level_node_ = old;
    return result;
  }

private:
  Probe *current_probe() const
  {
    return dynamic_cast<Probe *>(top_level_node_);
  }

  std::optional<Expression> fold_builtin(const std::string &ident,
                                         const Location &loc)
  {
    if (ident == "__builtin_config") {
      return expand_config(loc);
    }
    if (ident == "__builtin_arch") {
      std::stringstream ss;
      ss << bpftrace::arch::current();
      return ast_.make_node<String>(loc, ss.str());
    }
    if (ident == "__builtin_safe_mode") {
      return ast_.make_node<Boolean>(loc, bpftrace_.safe_mode_);
    }

    auto *probe = current_probe();
    if (probe == nullptr) {
      return std::nullopt;
    }

    if (ident == "__builtin_probe") {
      return ast_.make_node<String>(loc,
                                    probe->attach_points.empty()
                                        ? "none"
                                        : probe->attach_points.front()->name());
    }
    if (ident == "__builtin_probetype") {
      return ast_.make_node<String>(
          loc,
          probe->attach_points.empty()
              ? "none"
              : probetypeName(
                    probetype(probe->attach_points.front()->provider)));
    }
    if (ident == "__builtin_elf_is_exe") {
      return ast_.make_node<Boolean>(
          loc, util::is_exe(probe->attach_points.front()->target));
    }
    if (ident == "__builtin_elf_ino") {
      return ast_.make_node<Integer>(
          loc, util::file_ino(probe->attach_points.front()->target));
    }

    return std::nullopt;
  }

  std::optional<Expression> expand_config(const Location &loc)
  {
    std::vector<std::pair<std::string, Expression>> args;
    auto &cfg = bpftrace_.config_;

    auto add_bool = [&](const char *key, bool val) {
      args.emplace_back(key, ast_.make_node<Boolean>(loc, val));
    };
    auto add_int = [&](const char *key, uint64_t val) {
      args.emplace_back(key, ast_.make_node<Integer>(loc, val));
    };
    auto add_str = [&](const char *key, const std::string &val) {
      args.emplace_back(key, ast_.make_node<String>(loc, val));
    };

    add_bool("cpp_demangle", cfg->cpp_demangle);
    add_bool("lazy_symbolication", cfg->lazy_symbolication);
    add_bool("print_maps_on_exit", cfg->print_maps_on_exit);
    add_bool("use_blazesym", cfg->use_blazesym);
    add_bool("show_debug_info", cfg->show_debug_info);

    add_int("log_size", cfg->log_size);
    add_int("max_bpf_progs", cfg->max_bpf_progs);
    add_int("max_cat_bytes", cfg->max_cat_bytes);
    add_int("max_map_keys", cfg->max_map_keys);
    add_int("max_probes", cfg->max_probes);
    add_int("max_strlen", cfg->max_strlen);
    add_int("on_stack_limit", cfg->on_stack_limit);
    add_int("perf_rb_pages", cfg->perf_rb_pages);

    add_str("str_trunc_trailer", cfg->str_trunc_trailer);

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
    return make_record(ast_, loc, std::move(args));
  }

  ASTContext &ast_;
  BPFtrace &bpftrace_;
  Node *top_level_node_ = nullptr;
};

} // namespace

Pass CreateBuiltinsPass()
{
  auto fn = [&](ASTContext &ast, BPFtrace &bpftrace) {
    Builtins builtins(ast, bpftrace);
    builtins.visit(ast.root);
    fold(ast);
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
