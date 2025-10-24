#include <optional>

#include "ast/ast.h"
#include "ast/passes/simplify_types.h"
#include "ast/visitor.h"
#include "struct.h"
#include "types.h"

namespace bpftrace::ast {

class SimplifyTypes : public Visitor<SimplifyTypes, std::optional<Expression>> {
public:
  SimplifyTypes(ASTContext &ast) : ast_(ast) {};

  using Visitor<SimplifyTypes, std::optional<Expression>>::visit;

  std::optional<Expression> visit(Binop &op);
  std::optional<Expression> visit(Expression &expr);

private:
  Expression create_land_chain(std::vector<Expression> &equal_exprs, Binop &op);
  ASTContext &ast_;
  int var_id_ = 0;
};

std::optional<Expression> SimplifyTypes::visit(Expression &expr)
{
  auto r = Visitor<SimplifyTypes, std::optional<Expression>>::visit(expr.value);
  if (r) {
    expr.value = r->value;
  }
  return std::nullopt;
}

Expression SimplifyTypes::create_land_chain(
    std::vector<Expression> &equal_exprs,
    Binop &op)
{
  auto end = equal_exprs.back();
  equal_exprs.pop_back();

  if (equal_exprs.empty()) {
    return end;
  }

  auto *and_binop = ast_.make_node<Binop>(
      op.loc, end, Operator::LAND, create_land_chain(equal_exprs, op));
  and_binop->result_type = CreateBool();

  return and_binop;
}

std::optional<Expression> SimplifyTypes::visit(Binop &op)
{
  visit(op.left);
  visit(op.right);

  if (op.op != Operator::EQ && op.op != Operator::NE) {
    return std::nullopt;
  }

  const SizedType &left_ty = op.left.type();
  const SizedType &right_ty = op.right.type();

  if (!left_ty.IsTupleTy() || !right_ty.IsTupleTy()) {
    return std::nullopt;
  }

  auto &left_fields = left_ty.GetFields();
  auto &right_fields = right_ty.GetFields();

  if (left_fields.size() != right_fields.size()) {
    // This is a semantic error
    return std::nullopt;
  }

  if (left_fields.empty()) {
    return ast_.make_node<Boolean>(op.loc, op.op == Operator::EQ);
  }

  // N.B. Because of the way we're accessing each field of the tuple
  // and essentially turning this:
  // `$x = ("hello", -6); $y = ("bye", -6); $x == $y`
  // into
  // `$x = ("hello", -6); $y = ("bye", -6); ($x.0 == $y.0 && $x.1 == $y.1)`
  // If the tuple contains an expression, it might not be evaluated
  // (due to short-circuiting) if previous elements in the tuple are not equal.
  // We're doing this instead of a generic memcmp because we can be less
  // strict about the inner types of the tuple matching up due to size
  // and alignment issus.
  // https://github.com/bpftrace/bpftrace/pull/4523#discussion_r2382109017
  std::vector<Expression> equal_exprs;
  StatementList block_stmts;

  Expression left_tuple;
  Expression right_tuple;

  // Assign tuples that aren't variables or map accesses to a temp variable
  // so that the entire tuple can be evaluated before comparison --
  // consider the case of `$a = 1; ({ 1 + $a }, 3) == (2, 3)`; these should
  // be equal
  var_id_++;
  if (op.left.is<Variable>() || op.left.is<MapAccess>()) {
    left_tuple = clone(ast_, op.left.loc(), op.left);
  } else {
    left_tuple = ast_.make_node<Variable>(op.left.loc(),
                                          "$$binop_tuple_left_" +
                                              std::to_string(var_id_));
    auto *left_var_assign = ast_.make_node<AssignVarStatement>(
        op.loc,
        clone(ast_, left_tuple.loc(), left_tuple.as<Variable>()),
        clone(ast_, op.left.loc(), op.left));
    block_stmts.emplace_back(left_var_assign);
  }

  if (op.right.is<Variable>() || op.right.is<MapAccess>()) {
    right_tuple = clone(ast_, op.right.loc(), op.right);
  } else {
    right_tuple = ast_.make_node<Variable>(op.right.loc(),
                                           "$$binop_tuple_right_" +
                                               std::to_string(var_id_));
    auto *right_var_assign = ast_.make_node<AssignVarStatement>(
        op.loc,
        clone(ast_, right_tuple.loc(), right_tuple.as<Variable>()),
        clone(ast_, op.right.loc(), op.right));
    block_stmts.emplace_back(right_var_assign);
  }

  for (size_t i = 0; i < left_fields.size(); ++i) {
    auto *left_tpa = ast_.make_node<TupleAccess>(op.loc, left_tuple, i);
    left_tpa->element_type = left_fields[i].type;

    auto *right_tpa = ast_.make_node<TupleAccess>(op.loc, right_tuple, i);
    right_tpa->element_type = right_fields[i].type;

    auto *equal = ast_.make_node<Binop>(
        op.loc, left_tpa, Operator::EQ, right_tpa);
    equal->result_type = CreateBool();

    auto expanded = Visitor<SimplifyTypes, std::optional<Expression>>::visit(
        equal);

    equal_exprs.emplace_back(expanded ? *expanded : equal);
  }

  auto land_chain = create_land_chain(equal_exprs, op);
  if (op.op == Operator::NE) {
    auto *not_binop = ast_.make_node<Unop>(op.loc, land_chain, Operator::LNOT);
    not_binop->result_type = CreateBool();
    return ast_.make_node<BlockExpr>(op.loc, std::move(block_stmts), not_binop);
  } else {
    return ast_.make_node<BlockExpr>(op.loc,
                                     std::move(block_stmts),
                                     land_chain);
  }
}

void simplify(ASTContext &ast, Expression &expr)
{
  SimplifyTypes simplifier(ast);
  simplifier.visit(expr);
}

} // namespace bpftrace::ast
