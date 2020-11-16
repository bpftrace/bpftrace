#pragma once

#include "visitors.h"
#include <ostream>

namespace bpftrace {
namespace ast {

class Printer : public ASTVisitor
{
public:
  explicit Printer(std::ostream &out, bool print_types = false)
      : out_(out), print_types(print_types)
  {
  }

  void print(Node *root);

  void visit(Integer &integer) override;
  void visit(PositionalParameter &param) override;
  void visit(String &string) override;
  void visit(StackMode &mode) override;
  void visit(Identifier &identifier) override;
  void visit(Builtin &builtin) override;
  void visit(Call &call) override;
  void visit(Map &map) override;
  void visit(Variable &var) override;
  void visit(Binop &binop) override;
  void visit(Unop &unop) override;
  void visit(Ternary &ternary) override;
  void visit(FieldAccess &acc) override;
  void visit(ArrayAccess &arr) override;
  void visit(Cast &cast) override;
  void visit(Tuple &tuple) override;
  void visit(ExprStatement &expr) override;
  void visit(AssignMapStatement &assignment) override;
  void visit(AssignVarStatement &assignment) override;
  void visit(If &if_block) override;
  void visit(Unroll &unroll) override;
  void visit(While &while_block) override;
  void visit(Jump &jump) override;
  void visit(Predicate &pred) override;
  void visit(AttachPoint &ap) override;
  void visit(Probe &probe) override;
  void visit(Program &program) override;

  int depth_ = 0;

private:
  std::ostream &out_;
  bool print_types = false;

  std::string type(const SizedType &ty);
};

} // namespace ast
} // namespace bpftrace
