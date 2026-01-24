#include "ast/passes/cast_creator.h"
#include "ast/ast.h"
#include "bpftrace.h"
#include "log.h"
#include "types.h"

#include <functional>

namespace bpftrace::ast {

bool try_element_cast(ASTContext &ctx,
                      Expression &elem,
                      const SizedType &expr_type,
                      const SizedType &target_type);

bool try_tuple_cast(ASTContext &ctx,
                    Expression &exp,
                    const SizedType &expr_type,
                    const SizedType &target_type)
{
  if (auto *block_expr = exp.as<BlockExpr>()) {
    return try_tuple_cast(ctx, block_expr->expr, expr_type, target_type);
  }

  if (!exp.is<Variable>() && !exp.is<TupleAccess>() && !exp.is<MapAccess>() &&
      !exp.is<Tuple>() && !exp.is<FieldAccess>() && !exp.is<Unop>()) {
    LOG(BUG) << "Unexpected expression kind: try_tuple_cast";
  }

  ExpressionList expr_list = {};

  for (size_t i = 0; i < target_type.GetFields().size(); ++i) {
    auto &expr_field_ty = expr_type.GetField(i).type;
    auto &target_field_ty = target_type.GetField(i).type;
    Expression elem;
    if (auto *tuple_literal = exp.as<Tuple>()) {
      elem = clone(ctx,
                   tuple_literal->elems.at(i).loc(),
                   tuple_literal->elems.at(i));
    } else {
      elem = ctx.make_node<TupleAccess>(Location(exp.loc()),
                                        clone(ctx, exp.loc(), exp),
                                        i);
      elem.as<TupleAccess>()->element_type = expr_field_ty;
    }
    if (!try_element_cast(ctx, elem, expr_field_ty, target_field_ty)) {
      return false;
    }
    expr_list.emplace_back(std::move(elem));
  }

  exp = ctx.make_node<Tuple>(Location(exp.loc()), std::move(expr_list));
  exp.as<Tuple>()->tuple_type = target_type;

  return true;
}

bool try_record_cast(ASTContext &ctx,
                     Expression &exp,
                     const SizedType &expr_type,
                     const SizedType &target_type)
{
  if (auto *block_expr = exp.as<BlockExpr>()) {
    return try_record_cast(ctx, block_expr->expr, expr_type, target_type);
  }

  if (!exp.is<Variable>() && !exp.is<FieldAccess>() && !exp.is<MapAccess>() &&
      !exp.is<Record>() && !exp.is<TupleAccess>() && !exp.is<Unop>()) {
    LOG(BUG) << "Unexpected expression kind: try_record_cast";
  }

  std::unordered_map<size_t, NamedArgument *> named_arg_map;

  for (size_t i = 0; i < expr_type.GetFields().size(); ++i) {
    const auto &target_field = target_type.GetField(i);
    const auto &expr_field_ty = expr_type.GetField(target_field.name).type;
    const auto &target_field_ty = target_field.type;
    Expression elem;
    if (auto *record_literal = exp.as<Record>()) {
      auto field_idx = expr_type.GetFieldIdx(target_field.name);
      elem = clone(ctx,
                   record_literal->elems.at(field_idx)->expr.loc(),
                   record_literal->elems.at(field_idx)->expr);
    } else {
      elem = ctx.make_node<FieldAccess>(Location(exp.loc()),
                                        clone(ctx, exp.loc(), exp),
                                        target_field.name);
      elem.as<FieldAccess>()->field_type = expr_field_ty;
    }
    if (!try_element_cast(ctx, elem, expr_field_ty, target_field_ty)) {
      return false;
    }
    auto *named_arg = ctx.make_node<NamedArgument>(Location(exp.loc()),
                                                   target_field.name,
                                                   std::move(elem));
    named_arg_map[expr_type.GetFieldIdx(target_field.name)] = named_arg;
  }

  // Maintain the ordering for the current type
  NamedArgumentList named_args = {};
  for (size_t i = 0; i < expr_type.GetFields().size(); ++i) {
    named_args.emplace_back(named_arg_map[i]);
  }

  exp = ctx.make_node<Record>(Location(exp.loc()), std::move(named_args));
  exp.as<Record>()->record_type = target_type;

  return true;
}

bool try_int_cast(ASTContext &ctx,
                  Expression &exp,
                  const SizedType &expr_type,
                  const SizedType &target_type)
{
  // We don't need a cast if it's a literal
  if (auto *integer = exp.as<Integer>()) {
    if (target_type.IsSigned()) {
      auto signed_ty = ast::get_signed_integer_type(integer->value);
      if (!signed_ty || !signed_ty->FitsInto(target_type)) {
        // The integer is too large
        return false;
      }
    } else {
      auto unsigned_ty = ast::get_integer_type(integer->value);
      if (!unsigned_ty.FitsInto(target_type)) {
        // The integer is too large
        return false;
      }
    }
    exp = ctx.make_node<Integer>(
        Location(exp.loc()), integer->value, target_type, integer->original);
    return true;
  } else if (auto *negative_integer = exp.as<NegativeInteger>()) {
    if (!target_type.IsSigned()) {
      return false;
    }

    auto signed_ty = ast::get_signed_integer_type(negative_integer->value);
    if (!signed_ty.FitsInto(target_type)) {
      // The integer is too large
      return false;
    }

    exp = ctx.make_node<NegativeInteger>(Location(exp.loc()),
                                         negative_integer->value,
                                         target_type);
    return true;
  }

  if (!expr_type.FitsInto(target_type) && !expr_type.IsCastableMapTy()) {
    return false;
  }

  auto *typeof_r = ctx.make_node<Typeof>(Location(exp.loc()), target_type);
  exp = ctx.make_node<Cast>(Location(exp.loc()),
                            typeof_r,
                            clone(ctx, exp.loc(), exp));

  return true;
}

bool try_string_cast(ASTContext &ctx,
                     Expression &exp,
                     const SizedType &expr_type,
                     const SizedType &target_type)
{
  if (exp.type().GetSize() == target_type.GetSize()) {
    return true;
  }

  if (!expr_type.FitsInto(target_type)) {
    return false;
  }

  auto *typeof_r = ctx.make_node<Typeof>(Location(exp.loc()), target_type);
  exp = ctx.make_node<Cast>(Location(exp.loc()),
                            typeof_r,
                            clone(ctx, exp.loc(), exp));
  return true;
}

bool try_element_cast(ASTContext &ctx,
                      Expression &elem,
                      const SizedType &expr_type,
                      const SizedType &target_type)
{
  if (expr_type == target_type) {
    return true;
  }

  // No when both are castable map types
  if (expr_type.GetTy() == target_type.GetTy() && expr_type.IsCastableMapTy()) {
    return true;
  }

  if ((expr_type.IsIntegerTy() || expr_type.IsCastableMapTy()) &&
      (target_type.IsIntegerTy() || target_type.IsCastableMapTy())) {
    return try_int_cast(ctx, elem, expr_type, target_type);
  }

  if (expr_type.GetTy() != target_type.GetTy()) {
    return false;
  }

  if (target_type.IsStringTy()) {
    return try_string_cast(ctx, elem, expr_type, target_type);
  } else if (target_type.IsTupleTy()) {
    return try_tuple_cast(ctx, elem, expr_type, target_type);
  } else if (target_type.IsRecordTy()) {
    return try_record_cast(ctx, elem, expr_type, target_type);
  }

  return false;
}

CastCreator::CastCreator(ASTContext &ast, BPFtrace &bpftrace)
    : ctx_(ast), bpftrace_(bpftrace)
{
}

void CastCreator::visit(AssignMapStatement &assignment)
{
  visit(assignment.map_access);
  visit(assignment.expr);

  const auto &expr_type = assignment.expr.type();
  const auto &value_type = assignment.map_access->map->value_type;

  if (value_type == expr_type) {
    return;
  }

  if (!try_element_cast(ctx_, assignment.expr, expr_type, value_type)) {
    assignment.addError() << "Type mismatch for "
                          << assignment.map_access->map->ident << ": "
                          << "trying to assign value of type '" << expr_type
                          << "' when map already has a value type '"
                          << value_type << "'";
  }
}

void CastCreator::visit(AssignVarStatement &assignment)
{
  visit(assignment.expr);
  visit(assignment.var_decl);

  const auto &expr_type = assignment.expr.type();
  const auto &var_type = assignment.var()->type();

  if (var_type == expr_type) {
    return;
  }

  if (!try_element_cast(ctx_, assignment.expr, expr_type, var_type)) {
    assignment.addError() << "Type mismatch for " << assignment.var()->ident
                          << ": "
                          << "trying to assign value of type '" << expr_type
                          << "' when variable already has a type '" << var_type
                          << "'";
  }
}

void CastCreator::visit(Binop &op)
{
  visit(op.left);
  visit(op.right);

  const auto &left_type = op.left.type();
  const auto &right_type = op.right.type();
  if (left_type == right_type) {
    return;
  }

  auto promoted = get_promoted_type(left_type, right_type);
  if (promoted) {
    try_element_cast(ctx_, op.left, left_type, *promoted);
    try_element_cast(ctx_, op.right, right_type, *promoted);
  }
}

void CastCreator::visit(BlockExpr &block)
{
  visit(block.stmts);
  visit(block.expr);
}

void CastCreator::visit(Cast &cast)
{
  visit(cast.expr);
  visit(cast.typeof);
}

void CastCreator::visit(IfExpr &if_expr)
{
  visit(if_expr.cond);
  visit(if_expr.left);
  visit(if_expr.right);

  const auto &result_type = if_expr.result_type;
  const auto &left_type = if_expr.left.type();
  const auto &right_type = if_expr.right.type();

  if (result_type != left_type) {
    if (!try_element_cast(ctx_, if_expr.left, left_type, result_type)) {
      if_expr.addError()
          << "Branches must return the same type or compatible types: "
          << "have '" << left_type << "' and '" << right_type << "'";
    }
  }

  if (result_type != right_type) {
    if (!try_element_cast(ctx_, if_expr.right, right_type, result_type)) {
      if_expr.addError()
          << "Branches must return the same type or compatible types: "
          << "have '" << left_type << "' and '" << right_type << "'";
    }
  }
}

void CastCreator::visit(Jump &jump)
{
  if (jump.ident == JumpType::RETURN) {
    visit(jump.return_value);
    if (dynamic_cast<Probe *>(top_level_node_)) {
      if (jump.return_value.has_value()) {
        const auto &ty = jump.return_value->type();
        if (ty.IsIntegerTy() && ty.GetSize() != 8) {
          // Probes always return 64 bit ints
          try_element_cast(ctx_, *jump.return_value, ty, CreateInt64());
        }
      }
    } else if (auto *subprog = dynamic_cast<Subprog *>(top_level_node_)) {
      if (!jump.return_value.has_value()) {
        if (!subprog->return_type->type().IsVoidTy()) {
          jump.addError() << "Function " << subprog->name << " is of type "
                          << subprog->return_type->type() << ", cannot return "
                          << CreateVoid();
          return;
        }
        return;
      }
      if (!try_element_cast(ctx_,
                            *jump.return_value,
                            jump.return_value->type(),
                            subprog->return_type->type())) {
        jump.addError() << "Function " << subprog->name << " is of type "
                        << subprog->return_type->type() << ", cannot return "
                        << jump.return_value->type();
        return;
      }
    }
  }
}

void CastCreator::visit(Map &map)
{
  if (map.value_type.IsNoneTy()) {
    map.addError() << "Undefined map: " + map.ident;
  }
}

void CastCreator::visit(MapAccess &acc)
{
  visit(acc.key);
  visit(acc.map);
  const auto &expr_type = acc.key.type();
  const auto &key_type = acc.map->key_type;

  if (key_type.IsNoneTy() || expr_type.IsNoneTy()) {
    return;
  }

  if (!try_element_cast(ctx_, acc.key, expr_type, key_type)) {
    acc.addError() << "Type mismatch for " << acc.map->ident << ": "
                   << "trying to assign key of type '" << expr_type
                   << "' when map already has a key type '" << key_type << "'";
  }
}

void CastCreator::visit(Probe &probe)
{
  top_level_node_ = &probe;
  visit(probe.attach_points);
  visit(probe.block);
}

void CastCreator::visit(Subprog &subprog)
{
  top_level_node_ = &subprog;

  for (SubprogArg *arg : subprog.args) {
    visit(arg->var);
  }

  visit(subprog.block);
  visit(subprog.return_type);
}

void CastCreator::visit(Variable &var)
{
  if (var.var_type.IsNoneTy()) {
    var.addError() << "Could not resolve the type of this variable";
  }
}

} // namespace bpftrace::ast
