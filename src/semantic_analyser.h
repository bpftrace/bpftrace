#pragma once

#include <sstream>

#include "ast.h"
#include "bpftrace.h"
#include "map.h"
#include "types.h"

namespace bpftrace {
namespace ast {

class SemanticAnalyser : public Visitor {
public:
  explicit SemanticAnalyser(Node *root, BPFtrace &bpftrace, std::ostream &out = std::cerr)
    : root_(root),
      bpftrace_(bpftrace),
      out_(out) { }

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
  int create_maps();

private:
  Node *root_;
  BPFtrace &bpftrace_;
  std::ostream &out_;
  std::ostringstream err_;
  int pass_;
  const int num_passes_ = 10;

  using Type = bpftrace::Type;
  Type type_;

  bool is_final_pass() const;

  std::map<std::string, Type> map_val_;
  std::map<std::string, std::vector<Type>> map_args_;
};

} // namespace ast
} // namespace bpftrace
