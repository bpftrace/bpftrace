#include "ast/passes/lift_context.h"
#include "ast/ast.h"
#include "ast/visitor.h"

namespace bpftrace::ast {

class ContextLifter : public Visitor<ContextLifter> {
public:
  explicit ContextLifter(ASTContext &ast) : ast_(ast) {};

  using Visitor<ContextLifter>::visit;
  void visit(Probe &probe);
  void visit(Expression &expr);

private:
  ASTContext &ast_;
  bool context_required_ = false;
};

void ContextLifter::visit(Probe &probe)
{
  context_required_ = false;
  Visitor<ContextLifter>::visit(probe);

  if (context_required_) {
    // Inject a declaration into the block. This gives something
    // that will automatically be plumbed in subsequent passes.
    probe.block->stmts.insert(
        probe.block->stmts.begin(),
        ast_.make_node<AssignVarStatement>(
            probe.block->loc,
            ast_.make_node<Variable>(probe.block->loc, "ctx"),
            ast_.make_node<Builtin>(probe.block->loc, "ctx")));
  }
}

void ContextLifter::visit(Expression &expr)
{
  if (auto *builtin = expr.as<Builtin>()) {
    if (builtin->ident == "ctx") {
      // Transform into a local variable that will automatically be
      // lifted in subsequent passes into loops and functions.
      expr.value = ast_.make_node<Variable>(builtin->loc, "ctx");
      context_required_ = true;
    }
  }
}

Pass CreateLiftContextPass()
{
  return Pass::create("LiftContext", [](ASTContext &ast) {
    ContextLifter lifter(ast);
    lifter.visit(*ast.root);
  });
}

} // namespace bpftrace::ast
