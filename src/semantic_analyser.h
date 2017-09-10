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
  void visit(String &string) override;
  void visit(Builtin &builtin) override;
  void visit(Call &call) override;
  void visit(Map &map) override;
  void visit(Variable &var) override;
  void visit(Binop &binop) override;
  void visit(Unop &unop) override;
  void visit(ExprStatement &expr) override;
  void visit(AssignMapStatement &assignment) override;
  void visit(AssignVarStatement &assignment) override;
  void visit(Predicate &pred) override;
  void visit(Probe &probe) override;
  void visit(Program &program) override;

  int analyse();
  int create_maps(bool debug=false);

private:
  Node *root_;
  BPFtrace &bpftrace_;
  std::ostream &out_;
  std::ostringstream err_;
  int pass_;
  const int num_passes_ = 10;

  bool is_final_pass() const;

  Probe *probe_;
  std::map<std::string, SizedType> variable_val_;
  std::map<std::string, SizedType> map_val_;
  std::map<std::string, MapKey> map_key_;
  bool needs_stackid_map_ = false;
  bool has_begin_probe_ = false;
  bool has_end_probe_ = false;
};

} // namespace ast
} // namespace bpftrace
