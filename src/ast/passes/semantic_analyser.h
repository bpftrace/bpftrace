#pragma once

#include <iostream>
#include <sstream>
#include <unordered_set>

#include "ast/pass_manager.h"
#include "ast/visitors.h"
#include "bpffeature.h"
#include "bpftrace.h"
#include "config.h"
#include "types.h"

namespace bpftrace {
namespace ast {

class SemanticAnalyser : public Visitor {
public:
  explicit SemanticAnalyser(ASTContext &ctx,
                            BPFtrace &bpftrace,
                            std::ostream &out = std::cerr,
                            bool has_child = true,
                            bool listing = false)
      : ctx_(ctx),
        bpftrace_(bpftrace),
        out_(out),
        listing_(listing),
        has_child_(has_child)
  {
  }

  explicit SemanticAnalyser(ASTContext &ctx, BPFtrace &bpftrace, bool has_child)
      : SemanticAnalyser(ctx, bpftrace, std::cerr, has_child)
  {
  }

  explicit SemanticAnalyser(ASTContext &ctx,
                            BPFtrace &bpftrace,
                            bool has_child,
                            bool listing)
      : SemanticAnalyser(ctx, bpftrace, std::cerr, has_child, listing)
  {
  }

  [[deprecated("Use Visit(Node *const &n) instead.")]]
  virtual inline void Visit(Node &n) override
  {
    n.accept(*this);
  }

  virtual inline void Visit(Node *const &n)
  {
    n->accept(*this);
  }

  virtual inline void Visit(Expression *&expr)
  {
    expr->accept(*this);
    dereference_if_needed(expr);
  }

  void visit(Integer &integer) override;
  void visit(PositionalParameter &param) override;
  void visit(String &string) override;
  void visit(StackMode &mode) override;
  void visit(Identifier &identifier) override;
  void visit(Builtin &builtin) override;
  void visit(Call &call) override;
  void visit(Sizeof &szof) override;
  void visit(Offsetof &ofof) override;
  void visit(Map &map) override;
  void visit(Variable &var) override;
  void visit(Binop &binop) override;
  void visit(Unop &unop) override;
  void visit(While &while_block) override;
  void visit(For &f) override;
  void visit(Jump &jump) override;
  void visit(Ternary &ternary) override;
  void visit(FieldAccess &acc) override;
  void visit(ArrayAccess &arr) override;
  void visit(Cast &cast) override;
  void visit(Tuple &tuple) override;
  void visit(ExprStatement &expr) override;
  void visit(AssignMapStatement &assignment) override;
  void visit(AssignVarStatement &assignment) override;
  void visit(AssignConfigVarStatement &assignment) override;
  void visit(VarDeclStatement &decl) override;
  void visit(If &if_block) override;
  void visit(Unroll &unroll) override;
  void visit(Predicate &pred) override;
  void visit(AttachPoint &ap) override;
  void visit(Probe &probe) override;
  void visit(Config &config) override;
  void visit(Subprog &subprog) override;
  void visit(Program &program) override;

  int analyse();

private:
  ASTContext &ctx_;
  BPFtrace &bpftrace_;
  std::ostream &out_;
  std::ostringstream err_;
  int pass_;
  const int num_passes_ = 10;
  bool listing_;

  bool is_final_pass() const;

  bool check_assignment(const Call &call,
                        bool want_map,
                        bool want_var,
                        bool want_map_key);
  [[nodiscard]] bool check_nargs(const Call &call, size_t expected_nargs);
  [[nodiscard]] bool check_varargs(const Call &call,
                                   size_t min_nargs,
                                   size_t max_nargs);
  bool check_arg(const Call &call,
                 Type type,
                 int arg_num,
                 bool want_literal = false,
                 bool fail = true);
  bool check_symbol(const Call &call, int arg_num);
  bool check_available(const Call &call, const AttachPoint &ap);

  void check_stack_call(Call &call, bool kernel);

  Probe *get_probe_from_scope(Scope *scope,
                              const location &loc,
                              std::string name = "");

  SizedType *get_map_type(const Map &map);
  SizedType *get_map_key_type(const Map &map);
  void assign_map_type(const Map &map, const SizedType &type);
  SizedType create_key_type(const SizedType &expr_type, const location &loc);
  void update_current_key(SizedType &current_key_type,
                          const SizedType &new_key_type);
  void validate_new_key(const SizedType &current_key_type,
                        const SizedType &new_key_type,
                        const std::string &map_ident,
                        const location &loc);
  bool update_string_size(SizedType &type, const SizedType &new_type);
  void validate_map_key(const SizedType &key, const location &loc);
  void resolve_struct_type(SizedType &type, const location &loc);

  void builtin_args_tracepoint(AttachPoint *attach_point, Builtin &builtin);
  ProbeType single_provider_type(Probe *probe);
  AddrSpace find_addrspace(ProbeType pt);

  void binop_ptr(Binop &op);
  void binop_int(Binop &op);
  void binop_array(Binop &op);
  void dereference_if_needed(Expression *&expr);

  bool has_error() const;
  bool in_loop(void)
  {
    return loop_depth_ > 0;
  };
  void accept_statements(StatementList &stmts);

  Scope *scope_;

  // Holds the function currently being visited by this SemanticAnalyser.
  std::string func_;
  // Holds the function argument index currently being visited by this
  // SemanticAnalyser.
  int func_arg_idx_ = -1;

  struct variable {
    SizedType type;
    bool can_resize;
    bool was_assigned;
  };

  std::map<Scope *, std::map<std::string, variable>> variables_;
  std::map<Scope *, std::map<std::string, location>> variable_decls_;
  std::map<std::string, SizedType> map_val_;
  std::map<std::string, SizedType> map_key_;

  uint32_t loop_depth_ = 0;
  bool has_begin_probe_ = false;
  bool has_end_probe_ = false;
  bool has_child_ = false;
  bool has_pos_param_ = false;
};

Pass CreateSemanticPass();
} // namespace ast
} // namespace bpftrace
