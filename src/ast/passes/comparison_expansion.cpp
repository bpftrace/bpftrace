#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <optional>
#include <regex>
#include <string>
#include <sys/stat.h>

#include "arch/arch.h"
#include "ast/ast.h"
#include "ast/async_event_types.h"
#include "ast/context.h"
#include "ast/helpers.h"
#include "ast/passes/comparison_expansion.h"
#include "ast/passes/fold_literals.h"
#include "ast/passes/map_sugar.h"
#include "ast/passes/named_param.h"
#include "ast/passes/type_system.h"
#include "ast/signal_bt.h"
#include "btf/compat.h"
#include "collect_nodes.h"
#include "config.h"
#include "log.h"
#include "probe_matcher.h"
#include "tracepoint_format_parser.h"
#include "types.h"
#include "usdt.h"
#include "util/paths.h"
#include "util/strings.h"
#include "util/system.h"
#include "util/wildcard.h"

namespace bpftrace::ast {

class CompareExpander
    : public Visitor<CompareExpander, std::optional<Expression>> {
public:
  CompareExpander(ASTContext &ast);

  using Visitor<CompareExpander, std::optional<Expression>>::visit;

  std::optional<Expression> visit(Binop &op);
  std::optional<Expression> visit(Expression &expr);

private:
  Expression create_land_chain(std::vector<Expression> &equal_exprs, Binop &op);
  ASTContext &ast_;
};

CompareExpander::CompareExpander(ASTContext &ast) : ast_(ast)
{
}

std::optional<Expression> CompareExpander::visit(Expression &expr)
{
  auto r = Visitor<CompareExpander, std::optional<Expression>>::visit(
      expr.value);
  if (r) {
    expr.value = r->value;
  }
  return std::nullopt;
}

Expression CompareExpander::create_land_chain(
    std::vector<Expression> &equal_exprs,
    Binop &op)
{
  auto end = equal_exprs.back();
  equal_exprs.pop_back();

  if (equal_exprs.empty()) {
    return end;
  }

  auto *and_binop = ast_.make_node<Binop>(end,
                                          Operator::LAND,
                                          create_land_chain(equal_exprs, op),
                                          Location(op.loc));
  and_binop->result_type = CreateBool();

  return and_binop;
}

std::optional<Expression> CompareExpander::visit(Binop &op)
{
  visit(op.left);
  visit(op.right);

  if (op.op != Operator::EQ && op.op != Operator::NE) {
    return std::nullopt;
  }

  const SizedType &left_ty = op.left.type();
  const SizedType &right_ty = op.right.type();

  // TODO add expansion for records
  if (!left_ty.IsTupleTy()) {
    return std::nullopt;
  }

  // By now both types should be validated as tuples with the same number of
  // elements
  auto &left_fields = left_ty.GetFields();
  auto &right_fields = right_ty.GetFields();

  if (left_fields.empty()) {
    return ast_.make_node<Boolean>(op.op == Operator::EQ, Location(op.loc));
  }

  std::vector<Expression> equal_exprs;
  for (size_t i = 0; i < left_fields.size(); ++i) {
    auto *left_tpa = ast_.make_node<TupleAccess>(op.left, i, Location(op.loc));
    left_tpa->element_type = left_fields[i].type;

    auto *right_tpa = ast_.make_node<TupleAccess>(op.right,
                                                  i,
                                                  Location(op.loc));
    right_tpa->element_type = right_fields[i].type;

    auto *equal = ast_.make_node<Binop>(
        left_tpa, Operator::EQ, right_tpa, Location(op.loc));
    equal->result_type = CreateBool();

    auto expanded = Visitor<CompareExpander, std::optional<Expression>>::visit(
        equal);

    equal_exprs.emplace_back(expanded ? *expanded : equal);
  }

  auto land_chain = create_land_chain(equal_exprs, op);
  if (op.op == Operator::NE) {
    auto *not_binop = ast_.make_node<Unop>(
        land_chain, Operator::LNOT, false, Location(op.loc));
    not_binop->result_type = CreateBool();
    return not_binop;
  } else {
    return land_chain;
  }
}

Pass CreateComparisonExpansionPass()
{
  auto fn = [](ASTContext &ast) {
    CompareExpander expander(ast);
    expander.visit(ast.root);
  };

  return Pass::create("ComparisonExpansion", fn);
}

} // namespace bpftrace::ast
