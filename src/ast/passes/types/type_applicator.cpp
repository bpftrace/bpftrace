#include "ast/passes/types/type_applicator.h"
#include "ast/ast.h"
#include "ast/passes/types/type_map.h"
#include "ast/visitor.h"

namespace bpftrace::ast {

namespace {

class TypeApplicator : public Visitor<TypeApplicator> {
public:
  explicit TypeApplicator(const TypeMap &type_map) : type_map_(type_map) {};

  using Visitor<TypeApplicator>::visit;

  void visit(ArrayAccess &arr);
  void visit(Binop &binop);
  void visit(Builtin &builtin);
  void visit(Call &call);
  void visit(Cast &cast);
  void visit(FieldAccess &acc);
  void visit(Identifier &identifier);
  void visit(IfExpr &if_expr);
  void visit(Map &map);
  void visit(MapAddr &map_addr);
  void visit(Record &record);
  void visit(Tuple &tuple);
  void visit(TupleAccess &acc);
  void visit(Unop &unop);
  void visit(Variable &var);
  void visit(VariableAddr &var_addr);

private:
  const TypeMap &type_map_;

  void apply(Node &node, SizedType &target)
  {
    const auto &type = type_map_.type(&node);
    if (!type.IsNoneTy()) {
      target = type;
    }
  }
};

void TypeApplicator::visit(ArrayAccess &arr)
{
  Visitor<TypeApplicator>::visit(arr);
  apply(arr, arr.element_type);
}

void TypeApplicator::visit(Binop &binop)
{
  Visitor<TypeApplicator>::visit(binop);
  apply(binop, binop.result_type);
}

void TypeApplicator::visit(Builtin &builtin)
{
  apply(builtin, builtin.builtin_type);
}

void TypeApplicator::visit(Call &call)
{
  Visitor<TypeApplicator>::visit(call);
  apply(call, call.return_type);
}

void TypeApplicator::visit(Cast &cast)
{
  // N.B. this can mutate the AST. Consider this example: `$a = (uint8)1 ==
  // (int8)-1;`. Both casts are holding a SizedType as the record (not an
  // expression) so when the left and right types get promoted to an int16 these
  // two casts change to `$a = (int16)1 == (int16)-1;`. However a cast will be
  // inserted by CastCreator if the initial casts were expressions, e.g. `$a =
  // (typeof)1 == (int8)-1;`
  Visitor<TypeApplicator>::visit(cast);
  if (std::holds_alternative<SizedType>(cast.typeof->record)) {
    apply(cast, std::get<SizedType>(cast.typeof->record));
  }
}

void TypeApplicator::visit(FieldAccess &acc)
{
  Visitor<TypeApplicator>::visit(acc);
  apply(acc, acc.field_type);
}

void TypeApplicator::visit(IfExpr &if_expr)
{
  Visitor<TypeApplicator>::visit(if_expr);
  apply(if_expr, if_expr.result_type);
}

void TypeApplicator::visit(Identifier &identifier)
{
  apply(identifier, identifier.ident_type);
}

void TypeApplicator::visit(Map &map)
{
  const auto *key_type = type_map_.find_map_key_type(map.ident);
  if (key_type) {
    map.key_type = *key_type;
  }
  if (map.key_type.IsNoneTy()) {
    map.addError() << "Undefined map: " + map.ident;
  }
  const auto *val_type = type_map_.find_map_value_type(map.ident);
  if (val_type) {
    map.value_type = *val_type;
  }
  if (map.value_type.IsNoneTy()) {
    map.addError() << "Undefined map: " + map.ident;
  }
}

void TypeApplicator::visit(MapAddr &map_addr)
{
  Visitor<TypeApplicator>::visit(map_addr);
  apply(map_addr, map_addr.map_addr_type);
}

void TypeApplicator::visit(Record &record)
{
  Visitor<TypeApplicator>::visit(record);
  apply(record, record.record_type);
}

void TypeApplicator::visit(Tuple &tuple)
{
  Visitor<TypeApplicator>::visit(tuple);
  apply(tuple, tuple.tuple_type);
}

void TypeApplicator::visit(TupleAccess &acc)
{
  Visitor<TypeApplicator>::visit(acc);
  apply(acc, acc.element_type);
}

void TypeApplicator::visit(Unop &unop)
{
  Visitor<TypeApplicator>::visit(unop);
  apply(unop, unop.result_type);
}

void TypeApplicator::visit(Variable &var)
{
  apply(var, var.var_type);
  if (var.var_type.IsNoneTy()) {
    var.addError() << "Could not resolve the type of this variable";
  }
}

void TypeApplicator::visit(VariableAddr &var_addr)
{
  Visitor<TypeApplicator>::visit(var_addr);
  apply(var_addr, var_addr.var_addr_type);
}

} // namespace

void RunTypeApplicator(ASTContext &ast, const TypeMap &type_map)
{
  TypeApplicator(type_map).visit(ast.root);
}

} // namespace bpftrace::ast
