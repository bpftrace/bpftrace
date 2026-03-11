#include "ast/passes/types/cast_creator.h"
#include "ast/ast.h"
#include "ast/passes/map_sugar.h"
#include "ast/passes/types/type_map.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "log.h"
#include "types.h"

#include <functional>
#include <optional>
#include <variant>

namespace bpftrace::ast {

static std::optional<SizedType> try_expression_cast(
    ASTContext &ctx,
    Expression &expr,
    const SizedType &expr_type,
    const SizedType &target_type);

std::optional<SizedType> try_tuple_cast(ASTContext &ctx,
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
  std::vector<SizedType> element_types;

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
    }
    auto cast_type = try_expression_cast(
        ctx, elem, expr_field_ty, target_field_ty);
    if (!cast_type) {
      return std::nullopt;
    }
    element_types.emplace_back(*cast_type);
    expr_list.emplace_back(std::move(elem));
  }

  auto tuple_type = CreateTuple(Struct::CreateTuple(element_types));
  exp = ctx.make_node<Tuple>(Location(exp.loc()), std::move(expr_list));

  return tuple_type;
}

std::optional<SizedType> try_record_cast(ASTContext &ctx,
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

  std::unordered_map<size_t, std::pair<NamedArgument *, SizedType>>
      named_arg_map;

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
    }
    auto cast_type = try_expression_cast(
        ctx, elem, expr_field_ty, target_field_ty);
    if (!cast_type) {
      return std::nullopt;
    }
    auto *named_arg = ctx.make_node<NamedArgument>(Location(exp.loc()),
                                                   target_field.name,
                                                   std::move(elem));
    named_arg_map[expr_type.GetFieldIdx(target_field.name)] = { named_arg,
                                                                *cast_type };
  }

  // Keep the ordering for the current type to maintain evaluation order
  NamedArgumentList named_args = {};
  std::vector<SizedType> elements;
  std::vector<std::string_view> names;
  for (size_t i = 0; i < expr_type.GetFields().size(); ++i) {
    named_args.emplace_back(named_arg_map[i].first);
    names.emplace_back(named_arg_map[i].first->name);
    elements.emplace_back(named_arg_map[i].second);
  }

  auto record_type = CreateRecord(Struct::CreateRecord(elements, names));

  exp = ctx.make_node<Record>(Location(exp.loc()), std::move(named_args));

  return record_type;
}

static std::optional<SizedType> try_int_cast(ASTContext &ctx,
                                             Expression &exp,
                                             const SizedType &expr_type,
                                             const SizedType &target_type)
{
  if (auto *integer = exp.as<Integer>()) {
    if (target_type.IsSigned()) {
      auto signed_ty = ast::get_signed_integer_type(integer->value);
      if (!signed_ty || !signed_ty->FitsInto(target_type)) {
        // The integer is too large
        return std::nullopt;
      }
    } else {
      auto unsigned_ty = ast::get_integer_type(integer->value);
      if (!unsigned_ty.FitsInto(target_type)) {
        // The integer is too large
        return std::nullopt;
      }
    }
  } else if (auto *negative_integer = exp.as<NegativeInteger>()) {
    if (!target_type.IsSigned()) {
      return std::nullopt;
    }

    auto signed_ty = ast::get_signed_integer_type(negative_integer->value);
    if (!signed_ty.FitsInto(target_type)) {
      // The integer is too large
      return std::nullopt;
    }
  }

  if (!expr_type.FitsInto(target_type) && !expr_type.IsCastableMapTy() &&
      !exp.is<Integer>() && !exp.is<NegativeInteger>()) {
    return std::nullopt;
  }

  auto *typeof_r = ctx.make_node<Typeof>(Location(exp.loc()), target_type);
  exp = ctx.make_node<Cast>(Location(exp.loc()),
                            typeof_r,
                            clone(ctx, exp.loc(), exp));

  return target_type;
}

static std::optional<SizedType> try_string_cast(ASTContext &ctx,
                                                Expression &exp,
                                                const SizedType &expr_type,
                                                const SizedType &target_type)
{
  if (expr_type.GetSize() == target_type.GetSize()) {
    return target_type;
  }

  if (!expr_type.FitsInto(target_type)) {
    return std::nullopt;
  }

  auto *typeof_r = ctx.make_node<Typeof>(Location(exp.loc()), target_type);
  exp = ctx.make_node<Cast>(Location(exp.loc()),
                            typeof_r,
                            clone(ctx, exp.loc(), exp));
  return target_type;
}

static std::optional<SizedType> try_expression_cast(
    ASTContext &ctx,
    Expression &expr,
    const SizedType &expr_type,
    const SizedType &target_type)
{
  if (expr_type == target_type) {
    return target_type;
  }

  // No when both are castable map types
  if (expr_type.GetTy() == target_type.GetTy() && expr_type.IsCastableMapTy()) {
    return target_type;
  }

  if ((expr_type.IsIntegerTy() || expr_type.IsCastableMapTy()) &&
      (target_type.IsIntegerTy() || target_type.IsCastableMapTy())) {
    return try_int_cast(ctx, expr, expr_type, target_type);
  }

  if (expr_type.GetTy() != target_type.GetTy()) {
    return std::nullopt;
  }

  if (target_type.IsStringTy()) {
    return try_string_cast(ctx, expr, expr_type, target_type);
  } else if (target_type.IsTupleTy()) {
    return try_tuple_cast(ctx, expr, expr_type, target_type);
  } else if (target_type.IsRecordTy()) {
    return try_record_cast(ctx, expr, expr_type, target_type);
  } else if (target_type.IsPtrTy()) {
    auto *typeof_r = ctx.make_node<Typeof>(Location(expr.loc()), target_type);
    expr = ctx.make_node<Cast>(Location(expr.loc()),
                               typeof_r,
                               clone(ctx, expr.loc(), expr));

    return target_type;
  } else if (target_type.IsBufferTy()) {
    // TODO: make it ok to cast buffer types to larger buffer types
    return target_type;
  }

  return std::nullopt;
}

namespace {

class CastCreator : public Visitor<CastCreator> {
public:
  explicit CastCreator(ASTContext &ast,
                       BPFtrace &bpftrace,
                       const TypeMap &type_map);

  using Visitor<CastCreator>::visit;
  void visit(AssignMapStatement &assignment);
  void visit(AssignVarStatement &assignment);
  void visit(Binop &binop);
  void visit(BlockExpr &block);
  void visit(Call &call);
  void visit(Cast &cast);
  void visit(For &f);
  void visit(IfExpr &if_expr);
  void visit(Jump &jump);
  void visit(MapAccess &acc);
  void visit(Probe &probe);
  void visit(Subprog &subprog);

private:
  std::optional<SizedType> cast_expression(Expression &expr,
                                           const SizedType &expr_type,
                                           const SizedType &target_type);

  ASTContext &ctx_;
  BPFtrace &bpftrace_;
  const TypeMap &type_map_;
  std::variant<std::monostate, Probe *, Subprog *> top_level_node_;
};

CastCreator::CastCreator(ASTContext &ast,
                         BPFtrace &bpftrace,
                         const TypeMap &type_map)
    : ctx_(ast), bpftrace_(bpftrace), type_map_(type_map)
{
}

std::optional<SizedType> CastCreator::cast_expression(
    Expression &expr,
    const SizedType &expr_type,
    const SizedType &target_type)
{
  return try_expression_cast(ctx_, expr, expr_type, target_type);
}

void CastCreator::visit(AssignMapStatement &assignment)
{
  visit(assignment.map_access);
  visit(assignment.expr);

  const auto &expr_type = type_map_.type(assignment.expr);
  const auto &value_type = type_map_.map_value_type(
      assignment.map_access->map->ident);

  if (value_type == expr_type) {
    return;
  }

  if (!cast_expression(assignment.expr, expr_type, value_type)) {
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

  const auto &expr_type = type_map_.type(assignment.expr);
  const auto &var_type = type_map_.type(assignment.var());

  if (var_type == expr_type) {
    return;
  }

  if (!cast_expression(assignment.expr, expr_type, var_type)) {
    assignment.addError() << "Type mismatch for " << assignment.var()->ident
                          << ": "
                          << "trying to assign value of type '" << expr_type
                          << "' when variable already has a type '" << var_type
                          << "'";
  }
}

void CastCreator::visit(Binop &binop)
{
  visit(binop.left);
  visit(binop.right);

  const auto &left_type = type_map_.type(binop.left);
  const auto &right_type = type_map_.type(binop.right);

  // N.B. don't upcast strings as there are cases when one size is the max
  // string size and we don't want to create a cast like (string[1024])"hi"
  if (left_type.IsStringTy() || right_type.IsStringTy()) {
    return;
  }

  if (is_comparison_op(binop.op)) {
    auto promoted = get_promoted_type(left_type, right_type);
    if (promoted) {
      cast_expression(binop.left, left_type, *promoted);
      cast_expression(binop.right, right_type, *promoted);
    }
  } else {
    const auto &result_type = type_map_.type(&binop);
    cast_expression(binop.left, left_type, result_type);
    cast_expression(binop.right, right_type, result_type);
  }
}

void CastCreator::visit(BlockExpr &block)
{
  visit(block.stmts);
  visit(block.expr);
}

void CastCreator::visit(Call &call)
{
  for (auto &varg : call.vargs) {
    visit(varg);
  }

  if (getAssignRewriteFuncs().contains(call.func)) {
    if (auto *map = call.vargs.at(0).as<Map>()) {
      cast_expression(call.vargs.at(1),
                      type_map_.type(call.vargs.at(1)),
                      type_map_.map_key_type(map->ident));
    }
  } else if (call.func == "percpu_kaddr") {
    if (call.vargs.size() == 2) {
      auto arg_type = type_map_.type(call.vargs.at(1));
      if (arg_type != CreateUInt32() && arg_type.IsIntegerTy()) {
        auto *typeof_c = ctx_.make_node<Typeof>(
            Location(call.vargs.at(1).loc()), CreateUInt32());
        call.vargs.at(1) = ctx_.make_node<Cast>(
            Location(call.vargs.at(1).loc()),
            typeof_c,
            clone(ctx_, call.vargs.at(1).loc(), call.vargs.at(1)));
      }
    }
  } else if (call.func == "usym") {
    auto arg_type = type_map_.type(call.vargs.at(0));
    if (arg_type.IsIntegerTy() && arg_type.GetSize() != 8) {
      cast_expression(call.vargs.at(0),
                      type_map_.type(call.vargs.at(0)),
                      CreateUInt64());
    }
  }
}

void CastCreator::visit(Cast &cast)
{
  visit(cast.expr);
  visit(cast.typeof);
}

void CastCreator::visit(For &f)
{
  visit(f.decl);
  visit(f.block);

  if (auto *map = f.iterable.as<Map>()) {
    visit(map);
  } else if (auto *range = f.iterable.as<Range>()) {
    visit(range->start);
    visit(range->end);

    const auto &start_type = type_map_.type(range->start);
    const auto &end_type = type_map_.type(range->end);
    if (start_type == end_type) {
      return;
    }
    auto larger = start_type.GetSize() > end_type.GetSize() ? start_type
                                                            : end_type;
    cast_expression(range->start, start_type, larger);
    cast_expression(range->end, end_type, larger);
  }
}

void CastCreator::visit(IfExpr &if_expr)
{
  visit(if_expr.cond);
  visit(if_expr.left);
  visit(if_expr.right);

  const auto &result_type = type_map_.type(&if_expr);
  const auto &left_type = type_map_.type(if_expr.left);
  const auto &right_type = type_map_.type(if_expr.right);

  if (result_type != left_type) {
    if (!cast_expression(if_expr.left, left_type, result_type)) {
      LOG(BUG) << "IfExpr left should be castable";
    }
  }

  if (result_type != right_type) {
    if (!cast_expression(if_expr.right, right_type, result_type)) {
      LOG(BUG) << "IfExpr right should be castable";
    }
  }
}

void CastCreator::visit(Jump &jump)
{
  if (jump.ident == JumpType::RETURN) {
    visit(jump.return_value);
    if (std::holds_alternative<Probe *>(top_level_node_)) {
      if (jump.return_value.has_value()) {
        const auto &ty = type_map_.type(*jump.return_value);
        if (ty.IsIntegerTy() && ty.GetSize() != 8) {
          // Probes always return 64 bit ints
          cast_expression(*jump.return_value, ty, CreateInt64());
        }
      }
    } else if (auto **subprog_ptr = std::get_if<Subprog *>(&top_level_node_)) {
      auto *subprog = *subprog_ptr;
      const auto &return_type = type_map_.type(subprog->return_type);
      if (!jump.return_value.has_value()) {
        if (!return_type.IsVoidTy()) {
          jump.addError() << "Function " << subprog->name << " is of type "
                          << return_type << ", cannot return " << CreateVoid();
          return;
        }
        return;
      }
      if (!cast_expression(*jump.return_value,
                           type_map_.type(*jump.return_value),
                           return_type)) {
        jump.addError() << "Function " << subprog->name << " is of type "
                        << return_type << ", cannot return "
                        << type_map_.type(*jump.return_value);
        return;
      }
    }
  }
}

void CastCreator::visit(MapAccess &acc)
{
  visit(acc.key);
  visit(acc.map);
  const auto &expr_type = type_map_.type(acc.key);
  const auto &key_type = type_map_.map_key_type(acc.map->ident);

  if (key_type.IsNoneTy() || expr_type.IsNoneTy()) {
    return;
  }

  if (!cast_expression(acc.key, expr_type, key_type)) {
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

} // namespace

void RunCastCreator(ASTContext &ast,
                    BPFtrace &bpftrace,
                    const TypeMap &type_map)
{
  CastCreator(ast, bpftrace, type_map).visit(ast.root);
}

} // namespace bpftrace::ast
