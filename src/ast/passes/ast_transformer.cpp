#include "ast/passes/ast_transformer.h"
#include "ast/ast.h"
#include "ast/passes/cast_creator.h"
#include "ast/passes/macro_expansion.h"
#include "struct.h"
#include "types.h"

namespace bpftrace::ast {

std::optional<Expression> AstTransformer::visit(Binop &binop)
{
  visit(binop.left);
  visit(binop.right);

  const auto &lht = get_type(&binop.left.node());
  const auto &rht = get_type(&binop.right.node());

  if (binop.op != Operator::EQ && binop.op != Operator::NE)
    return std::nullopt;

  if (!lht.IsTupleTy() && !lht.IsRecordTy())
    return std::nullopt;

  if (!lht.IsCompatible(rht))
    return std::nullopt;

  if (binop.left.is_literal() && binop.right.is_literal()) {
    // This will get folded.
    return std::nullopt;
  }

  bool is_tuple = lht.IsTupleTy();
  auto updatedTy = is_tuple ? get_promoted_tuple(lht, rht)
                            : get_promoted_record(lht, rht);
  if (!updatedTy) {
    binop.addError() << "Type mismatch for '" << opstr(binop) << "': comparing "
                     << lht << " with " << rht;
    return std::nullopt;
  }

  if (*updatedTy != lht) {
    if (is_tuple) {
      try_tuple_cast(ast_, binop.left, lht, *updatedTy);
    } else {
      try_record_cast(ast_, binop.left, lht, *updatedTy);
    }
  }
  if (*updatedTy != rht) {
    if (is_tuple) {
      try_tuple_cast(ast_, binop.right, rht, *updatedTy);
    } else {
      try_record_cast(ast_, binop.right, rht, *updatedTy);
    }
  }

  bool types_equal = binop.left.type() == binop.right.type();

  auto *size = ast_.make_node<Integer>(binop.loc,
                                       updatedTy->GetSize(),
                                       CreateUInt64());
  // N.B. if the types aren't equal at this point it means that
  // we're dealing with record types that are same except for
  // their fields are in a different order so we need to use a
  // different memcmp that saves off both the left and right to
  // variables but sets the type of the right variable to the left
  // before assignment (e.g. `let $right: typeof($left) = right;`)
  // as this ensures the temporary `$right` variable has the same
  // field ordering as the `$left`.
  auto *call = ast_.make_node<Call>(binop.loc,
                                    types_equal ? "memcmp" : "memcmp_record",
                                    ExpressionList{
                                        binop.left, binop.right, size });
  auto *typeof_node = ast_.make_node<Typeof>(binop.loc, CreateBool());
  auto *cast = ast_.make_node<Cast>(binop.loc, typeof_node, call);
  if (binop.op == Operator::NE) {
    return cast;
  } else {
    return ast_.make_node<Unop>(binop.loc, cast, Operator::LNOT);
  }
}

std::optional<Expression> AstTransformer::visit(Expression &expr)
{
  auto r = Visitor<AstTransformer, std::optional<Expression>>::visit(
      expr.value);
  if (r) {
    had_transforms_ = true;
    expr.value = r->value;
    expand_macro(ast_, expr, macro_registry_);
  }
  return std::nullopt;
}

std::optional<Expression> AstTransformer::visit(FieldAccess &acc)
{
  visit(acc.expr);

  // FieldAccesses will automatically resolve through any number of pointer
  // dereferences. For now, we inject the `Unop` operator directly, as codegen
  // stores the underlying structs as pointers anyways. In the future, we will
  // likely want to do this in a different way if we are tracking l-values.
  auto type = get_type(&acc.expr.node());
  while (type.IsPtrTy()) {
    auto *unop = ast_.make_node<Unop>(acc.expr.node().loc,
                                      acc.expr,
                                      Operator::MUL);
    unop->result_type = type.GetPointeeTy();
    if (type.IsCtxAccess())
      unop->result_type.MarkCtxAccess();
    unop->result_type.is_internal = type.is_internal;
    unop->result_type.SetAS(type.GetAS());
    acc.expr.value = unop;
    had_transforms_ = true;
    type = unop->result_type;
  }

  return std::nullopt;
}

std::optional<Expression> AstTransformer::visit(Offsetof &offof)
{
  SizedType cstruct;
  if (std::holds_alternative<SizedType>(offof.record)) {
    cstruct = std::get<SizedType>(offof.record);
  } else {
    cstruct = get_type(&std::get<Expression>(offof.record).node());
  }

  if (cstruct.IsNoneTy()) {
    return std::nullopt;
  }

  size_t offset = 0;
  for (const auto &field : offof.field) {
    if (!cstruct.IsCStructTy() || !cstruct.HasField(field)) {
      return std::nullopt;
    }
    const auto &f = cstruct.GetField(field);
    offset += f.offset;
    cstruct = f.type;
  }

  return ast_.make_node<Integer>(Location(offof.loc), offset);
}

std::optional<Expression> AstTransformer::visit(Sizeof &szof)
{
  size_t size = 0;
  if (std::holds_alternative<SizedType>(szof.record)) {
    auto &ty = std::get<SizedType>(szof.record);
    if (ty.IsNoneTy()) {
      return std::nullopt;
    }
    size = ty.GetSize();
  } else {
    const auto &ty = get_type(&std::get<Expression>(szof.record).node());
    if (ty.IsNoneTy()) {
      return std::nullopt;
    }
    size = ty.GetSize();
  }

  return ast_.make_node<Integer>(Location(szof.loc), size);
}

std::optional<Expression> AstTransformer::visit(Typeinfo &typeinfo)
{
  const auto &type = get_type(typeinfo.typeof);
  if (type.IsNoneTy()) {
    return std::nullopt;
  }

  // We currently lack a globally-unique enumeration of types. For
  // simplicity, just use the type string with a placeholder identifier.
  auto *id = ast_.make_node<Integer>(typeinfo.loc, 0);
  auto *base_ty = ast_.make_node<String>(typeinfo.loc, to_string(type.GetTy()));
  auto *full_ty = ast_.make_node<String>(typeinfo.loc, typestr(type));

  std::vector<SizedType> elements = { CreateUInt64(),
                                      base_ty->type(),
                                      full_ty->type() };
  std::vector<std::string_view> names = { "btf_id", "base_type", "full_type" };

  auto record_type = CreateRecord(Struct::CreateRecord(elements, names));

  auto *record = make_record(
      ast_,
      typeinfo.loc,
      { { "btf_id", id }, { "base_type", base_ty }, { "full_type", full_ty } });

  record->record_type = record_type;

  return record;
}

} // namespace bpftrace::ast
