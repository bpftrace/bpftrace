#pragma once

#include <ostream>

#include "ast/visitor.h"

namespace bpftrace {
namespace ast {

class Printer : public Visitor<Printer> {
public:
  explicit Printer(ASTContext &ctx, std::ostream &out)
      : Visitor<Printer>(ctx), out_(out)
  {
  }

  void print();

  using Visitor<Printer>::visit;
  void visit(Integer &integer);
  void visit(PositionalParameter &param);
  void visit(String &string);
  void visit(StackMode &mode);
  void visit(Identifier &identifier);
  void visit(Builtin &builtin);
  void visit(Call &call);
  void visit(Sizeof &szof);
  void visit(Offsetof &offof);
  void visit(Map &map);
  void visit(Variable &var);
  void visit(Binop &binop);
  void visit(Unop &unop);
  void visit(Ternary &ternary);
  void visit(FieldAccess &acc);
  void visit(ArrayAccess &arr);
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
  void visit(Program &program);

  int depth_ = -1;

private:
  std::ostream &out_;

  std::string type(const SizedType &ty);
};

} // namespace ast
} // namespace bpftrace
