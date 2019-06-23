#pragma once

#include <iostream>
#include <sstream>
#include <unordered_set>

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
  void visit(ExprStatement &expr) override;
  void visit(AssignMapStatement &assignment) override;
  void visit(AssignVarStatement &assignment) override;
  void visit(If &if_block) override;
  void visit(Unroll &unroll) override;
  void visit(Predicate &pred) override;
  void visit(AttachPoint &ap) override;
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

  bool check_assignment(const Call &call, bool want_map, bool want_var);
  bool check_nargs(const Call &call, size_t expected_nargs);
  bool check_varargs(const Call &call, size_t min_nargs, size_t max_nargs);
  bool check_arg(const Call &call, Type type, int arg_num, bool want_literal=false);
  bool check_alpha_numeric(const Call &call, int arg_num);

  void check_stack_call(Call &call, Type type);

  void assign_map_type(const Map &map, const SizedType &type);

  Probe *probe_;
  std::map<std::string, SizedType> variable_val_;
  std::map<std::string, SizedType> map_val_;
  std::map<std::string, MapKey> map_key_;
  std::map<std::string, ExpressionList> map_args_;
  std::unordered_set<StackType> needs_stackid_maps_;
  bool needs_join_map_ = false;
  bool has_begin_probe_ = false;
  bool has_end_probe_ = false;
};

} // namespace ast
} // namespace bpftrace
