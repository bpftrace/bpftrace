#include "ast/passes/test_return.h"
#include "ast/ast.h"
#include "ast/visitor.h"
#include "bpftrace.h"

namespace bpftrace::ast {

namespace {

// In a test probe, a non-zero return marks a failure. This pass rewrites each
// `return <expr>` in a test probe to `return (<expr> != 0 ? <line> : 0)`, so
// the returned value (which bpftrace reports) is the source line of the failing
// return.
class TestReturn : public Visitor<TestReturn> {
public:
  TestReturn(ASTContext &ast) : ast_(ast) {};

  using Visitor<TestReturn>::visit;

  void visit(Probe &probe);
  void visit(Jump &jump);

private:
  ASTContext &ast_;
  bool in_test_probe_ = false;
};

} // namespace

void TestReturn::visit(Probe &probe)
{
  if (probe.has_ap_of_probetype(ProbeType::test)) {
    in_test_probe_ = true;
    Visitor<TestReturn>::visit(probe);
    in_test_probe_ = false;
  }
}

void TestReturn::visit(Jump &jump)
{
  Visitor<TestReturn>::visit(jump);

  if (!in_test_probe_ || jump.ident != JumpType::RETURN ||
      !jump.return_value.has_value()) {
    return;
  }

  // Build `<return_value> != 0 ? <line> : 0`.
  auto *cond = ast_.make_node<Binop>(jump.loc,
                                     jump.return_value.value(),
                                     Operator::NE,
                                     ast_.make_node<Integer>(jump.loc, 0));
  auto *line = ast_.make_node<Integer>(jump.loc, jump.loc->line());
  auto *zero = ast_.make_node<Integer>(jump.loc, 0);
  jump.return_value = ast_.make_node<IfExpr>(jump.loc, cond, line, zero);
}

Pass CreateTestReturnPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &bpftrace) {
    if (bpftrace.run_tests_) {
      TestReturn tr(ast);
      tr.visit(ast.root);
    }
  };

  return Pass::create("TestReturn", fn);
}

} // namespace bpftrace::ast
