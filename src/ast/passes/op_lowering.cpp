#include <optional>

#include "ast/ast.h"
#include "ast/passes/op_lowering.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "log.h"

namespace bpftrace::ast {

namespace {

class OpLowering : public Visitor<OpLowering, std::optional<Expression>> {
public:
  OpLowering(ASTContext &ast) : ast_(ast) {};
  OpLowering(ASTContext &ast, BPFtrace &bpftrace)
      : ast_(ast), bpftrace_(std::ref(bpftrace)) {};

  using Visitor<OpLowering, std::optional<Expression>>::visit;

  std::optional<Expression> visit(Binop &op);
  std::optional<Expression> visit(Expression &expr);

private:
  ASTContext &ast_;
  std::optional<std::reference_wrapper<BPFtrace>> bpftrace_;
};

} // namespace

std::optional<Expression> OpLowering::visit(Binop &op)
{
  const auto &lht = op.left.type();
  const auto &rht = op.right.type();

  if (lht.IsTupleTy() && rht.IsTupleTy()) {
    assert(op.op == Operator::EQ || op.op == Operator::NE);
    assert(lht.GetSize() == rht.GetSize());
    auto *left_typeof = ast_.make_node<Typeof>(CreatePointer(CreateVoid()),
                                               Location(op.loc));
    auto *left_ptr = ast_.make_node<Cast>(left_typeof,
                                          op.left,
                                          Location(op.loc));

    auto *right_typeof = ast_.make_node<Typeof>(CreatePointer(CreateVoid()),
                                                Location(op.loc));
    auto *right_ptr = ast_.make_node<Cast>(right_typeof,
                                           op.right,
                                           Location(op.loc));

    auto *size_arg = ast_.make_node<Integer>(lht.GetSize(), Location(op.loc));

    auto *call = ast_.make_node<Call>("__memcmp",
                                      ExpressionList{
                                          left_ptr, right_ptr, size_arg },
                                      Location(op.loc));
    call->return_type = CreateBool();

    if (op.op == Operator::EQ) {
      return call;
    }

    auto *unop = ast_.make_node<Unop>(
        call, Operator::LNOT, false, Location(op.loc));
    unop->result_type = CreateBool();

    return unop;
  }

  return std::nullopt;
}

std::optional<Expression> OpLowering::visit(Expression &expr)
{
  auto r = Visitor<OpLowering, std::optional<Expression>>::visit(expr.value);
  if (r) {
    expr.value = r->value;
  }
  return std::nullopt;
}

Pass CreateOpLoweringPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &b) {
    OpLowering folder(ast, b);
    folder.visit(ast.root);
  };

  return Pass::create("OpLowering", fn);
}

} // namespace bpftrace::ast
