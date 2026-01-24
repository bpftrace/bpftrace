#pragma once

#include "ast/passes/type_resolver.h"
#include "ast/visitor.h"

namespace bpftrace::ast {

class TypeApplicator : public Visitor<TypeApplicator> {
public:
  explicit TypeApplicator(const ResolvedTypes &resolved_types)
      : resolved_types_(resolved_types) {};

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
  const ResolvedTypes &resolved_types_;

  void apply(Node &node, SizedType &target)
  {
    auto it = resolved_types_.find(&node);
    if (it != resolved_types_.end()) {
      target = it->second;
    }
  }
};

} // namespace bpftrace::ast
