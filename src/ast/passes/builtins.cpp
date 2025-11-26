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
  std::optional<Expression> check(const std::string &ident, Node &node);

private:
  ASTContext &ast_;
  BPFtrace &bpftrace_;
  Node *top_level_node_ = nullptr;
};

} // namespace

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
      auto *probe = dynamic_cast<Probe *>(top_level_node_);
      if (!probe) {
        LOG(BUG) << "Inner error: can't get probe for " << call.func;
        return std::nullopt;
      }
      ProbeType type = probetype(probe->attach_points.front()->provider);
      bpf_prog_type prog_type = progtype(type);
      return ast_.make_node<Boolean>(
          kfunc->loc,
          bpftrace_.feature_->kfunc_allowed(kfunc->value.c_str(), prog_type));
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
  top_level_node_ = &probe;
  return Visitor<Builtins, std::optional<Expression>>::visit(probe);
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
