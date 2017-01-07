#pragma once

#include <memory>
#include <sstream>

#include "ast.h"
#include "map.h"

namespace ebpf {
namespace bpftrace {
namespace ast {

class SemanticAnalyser : public Visitor {
public:
  explicit SemanticAnalyser(Node *root) : root_(root) { }

  void visit(Integer &integer) override;
  void visit(Builtin &builtin) override;
  void visit(Call &call) override;
  void visit(Map &map) override;
  void visit(Binop &binop) override;
  void visit(Unop &unop) override;
  void visit(ExprStatement &expr) override;
  void visit(AssignMapStatement &assignment) override;
  void visit(AssignMapCallStatement &assignment) override;
  void visit(Predicate &pred) override;
  void visit(Probe &probe) override;
  void visit(Program &program) override;

  int analyse();

private:
  Node *root_;
};

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
