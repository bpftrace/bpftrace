#pragma once

#include "ast.h"

namespace bpftrace {
namespace ast {

class Visitor
{
public:
  virtual ~Visitor() = default;
  virtual void visit(Integer &integer) = 0;
  virtual void visit(PositionalParameter &integer) = 0;
  virtual void visit(String &string) = 0;
  virtual void visit(Builtin &builtin) = 0;
  virtual void visit(Identifier &identifier) = 0;
  virtual void visit(StackMode &mode) = 0;
  virtual void visit(Call &call) = 0;
  virtual void visit(Map &map) = 0;
  virtual void visit(Variable &var) = 0;
  virtual void visit(Binop &binop) = 0;
  virtual void visit(Unop &unop) = 0;
  virtual void visit(Ternary &ternary) = 0;
  virtual void visit(FieldAccess &acc) = 0;
  virtual void visit(ArrayAccess &arr) = 0;
  virtual void visit(Cast &cast) = 0;
  virtual void visit(Tuple &tuple) = 0;
  virtual void visit(ExprStatement &expr) = 0;
  virtual void visit(AssignMapStatement &assignment) = 0;
  virtual void visit(AssignVarStatement &assignment) = 0;
  virtual void visit(If &if_block) = 0;
  virtual void visit(Jump &jump) = 0;
  virtual void visit(Unroll &unroll) = 0;
  virtual void visit(While &while_block) = 0;
  virtual void visit(Predicate &pred) = 0;
  virtual void visit(AttachPoint &ap) = 0;
  virtual void visit(Probe &probe) = 0;
  virtual void visit(Program &program) = 0;
};

class ASTVisitor : public Visitor
{
public:
  explicit ASTVisitor() = default;
  ~ASTVisitor() = default;

  ASTVisitor(const ASTVisitor &) = delete;
  ASTVisitor &operator=(const ASTVisitor &) = delete;
  ASTVisitor(ASTVisitor &&) = delete;
  ASTVisitor &operator=(ASTVisitor &&) = delete;

  virtual void Visit(Node *root)
  {
    root->accept(*this);
  };

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
};

} // namespace ast
} // namespace bpftrace
