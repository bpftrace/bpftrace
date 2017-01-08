#pragma once

#include <sstream>

#include "ast.h"
#include "bpftrace.h"
#include "map.h"

namespace ebpf {
namespace bpftrace {
namespace ast {

class SemanticAnalyser : public Visitor {
public:
  explicit SemanticAnalyser(Node *root, BPFtrace &bpftrace)
    : root_(root),
      bpftrace_(bpftrace) { }

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
  BPFtrace &bpftrace_;
  std::ostringstream err_;
  int pass_;

  using Type = ebpf::bpftrace::Type;
  Type type_;
};

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
