#pragma once

#include <ostream>

#include "ast/visitor.h"

namespace bpftrace::ast {

class Printer : public Visitor<Printer> {
public:
  explicit Printer(std::ostream &out) : out_(out)
  {
  }

  using Visitor<Printer>::visit;
  void visit(Integer &integer);
  void visit(NegativeInteger &integer);
  void visit(PositionalParameter &param);
  void visit(PositionalParameterCount &param);
  void visit(String &string);
  void visit(StackMode &mode);
  void visit(Identifier &identifier);
  void visit(Builtin &builtin);
  void visit(Call &call);
  void visit(Sizeof &szof);
  void visit(Offsetof &offof);
  void visit(Map &map);
  void visit(MapDeclStatement &decl);
  void visit(Variable &var);
  void visit(Binop &binop);
  void visit(Unop &unop);
  void visit(Ternary &ternary);
  void visit(FieldAccess &acc);
  void visit(ArrayAccess &arr);
  void visit(TupleAccess &acc);
  void visit(Cast &cast);
  void visit(Tuple &tuple);
  void visit(ExprStatement &expr);
  void visit(AssignMapStatement &assignment);
  void visit(AssignVarStatement &assignment);
  void visit(AssignConfigVarStatement &assignment);
  void visit(VarDeclStatement &decl);
  void visit(If &if_node);
  void visit(Unroll &unroll);
  void visit(While &while_block);
  void visit(For &for_loop);
  void visit(Config &config);
  void visit(Jump &jump);
  void visit(Predicate &pred);
  void visit(AttachPoint &ap);
  void visit(Probe &probe);
  void visit(Subprog &subprog);
  void visit(Import &imp);
  void visit(Program &program);

private:
  std::ostream &out_;
  int depth_ = 0;

  std::string type(const SizedType &ty);
};

} // namespace bpftrace::ast
