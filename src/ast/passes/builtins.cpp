#include <optional>

#include "arch/arch.h"
#include "ast/passes/builtins.h"
#include "ast/visitor.h"
#include "bpftrace.h"

namespace bpftrace::ast {

namespace {

class Builtins : public Visitor<Builtins, std::optional<Expression>> {
public:
  explicit Builtins(ASTContext &ast, BPFtrace &bpftrace)
      : ast_(ast), bpftrace_(bpftrace) {};

  using Visitor<Builtins, std::optional<Expression>>::visit;
  std::optional<Expression> visit(Builtin &builtin);
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
    return ast_.make_node<String>(ss.str(), Location(node.loc));
  }
  if (ident == "__builtin_safe_mode") {
    return ast_.make_node<Boolean>(bpftrace_.safe_mode_, Location(node.loc));
  }
  if (ident == "__builtin_probe") {
    if (auto *probe = dynamic_cast<Probe *>(top_level_node_)) {
      assert(probe->attach_points.size() == 1);
      return ast_.make_node<String>(probe->attach_points.front()->name(),
                                    Location(node.loc));
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
