#include <optional>

#include "ast/ast.h"
#include "ast/passes/call_injection.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "log.h"

namespace bpftrace::ast {

namespace {

class CallInjection : public Visitor<CallInjection, std::optional<Expression>> {
public:
  CallInjection(ASTContext &ast) : ast_(ast) {};
  CallInjection(ASTContext &ast, BPFtrace &bpftrace)
      : ast_(ast), bpftrace_(std::ref(bpftrace)) {};

  using Visitor<CallInjection, std::optional<Expression>>::visit;

  std::optional<Expression> visit(Binop &op);
  std::optional<Expression> visit(Expression &expr);

private:
  ASTContext &ast_;
  std::optional<std::reference_wrapper<BPFtrace>> bpftrace_;
};

} // namespace

std::optional<Expression> CallInjection::visit(Binop &op)
{
  const auto &lht = op.left.type();
  const auto &rht = op.right.type();

  if (lht.IsTupleTy() && rht.IsTupleTy()) {
    auto min_size = std::min(lht.GetSize(), rht.GetSize());
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

    auto *size_arg = ast_.make_node<Integer>(min_size, Location(op.loc));

    auto *call = ast_.make_node<Call>("__memcmp",
                                      ExpressionList{
                                          left_ptr, right_ptr, size_arg },
                                      Location(op.loc));
    call->return_type = CreateInt32();

    auto *call_typeof = ast_.make_node<Typeof>(CreateBool(), Location(op.loc));
    auto *cast = ast_.make_node<Cast>(call_typeof, call, Location(op.loc));

    if (op.op == Operator::EQ) {
      return cast;
    }

    auto *unop = ast_.make_node<Unop>(
        cast, Operator::LNOT, false, Location(op.loc));
    unop->result_type = CreateBool();

    return unop;
  }

  return std::nullopt;
}

std::optional<Expression> CallInjection::visit(Expression &expr)
{
  auto r = Visitor<CallInjection, std::optional<Expression>>::visit(expr.value);
  if (r) {
    expr.value = r->value;
  }
  return std::nullopt;
}

Pass CreateCallInjectionPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &b) {
    CallInjection folder(ast, b);
    folder.visit(ast.root);
  };

  return Pass::create("CallInjection", fn);
}

} // namespace bpftrace::ast
