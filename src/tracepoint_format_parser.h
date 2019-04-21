#pragma once

#include <istream>
#include <set>

#include "ast/ast.h"

namespace bpftrace {

namespace ast {

class TracepointArgsVisitor : public Visitor
{
public:
  ~TracepointArgsVisitor() override { }
  void visit(__attribute__((unused)) Integer &integer) override { };  // Leaf
  void visit(__attribute__((unused)) PositionalParameter &integer) override { };  // Leaf
  void visit(__attribute__((unused)) String &string) override { };  // Leaf
  void visit(__attribute__((unused)) StackMode &mode) override { };  // Leaf
  void visit(__attribute__((unused)) Identifier &identifier) override { };  // Leaf
  void visit(Builtin &builtin) override {  // Leaf
    if (builtin.ident == "args")
      probe_->need_tp_args_structs = true;
  };  // Leaf
  void visit(Call &call) override {
    if (call.vargs) {
      for (Expression *expr : *call.vargs) {
        expr->accept(*this);
      }
    }
  };
  void visit(Map &map) override {
    if (map.vargs) {
      for (Expression *expr : *map.vargs) {
        expr->accept(*this);
      }
    }
  };
  void visit(__attribute__((unused)) Variable &var) override { };  // Leaf
  void visit(Binop &binop) override {
    binop.left->accept(*this);
    binop.right->accept(*this);
  };
  void visit(Unop &unop) override {
    unop.expr->accept(*this);
  };
  void visit(Ternary &ternary) override {
    ternary.cond->accept(*this);
    ternary.left->accept(*this);
    ternary.right->accept(*this);
  };
  void visit(FieldAccess &acc) override {
    acc.expr->accept(*this);
  };
  void visit(ArrayAccess &acc) override {
    acc.expr->accept(*this);
  };
  void visit(Cast &cast) override {
    cast.expr->accept(*this);
  };
  void visit(ExprStatement &expr) override {
    expr.expr->accept(*this);
  };
  void visit(AssignMapStatement &assignment) override {
    assignment.map->accept(*this);
    assignment.expr->accept(*this);
  };
  void visit(AssignVarStatement &assignment) override {
    assignment.expr->accept(*this);
  };
  void visit(If &if_block) override {
    if_block.cond->accept(*this);

    for (Statement *stmt : *if_block.stmts) {
      stmt->accept(*this);
    }

    if (if_block.else_stmts) {
      for (Statement *stmt : *if_block.else_stmts) {
        stmt->accept(*this);
      }
    }
  };
  void visit(Unroll &unroll) override {
    for (Statement *stmt : *unroll.stmts) {
      stmt->accept(*this);
    }
  };
  void visit(Predicate &pred) override {
    pred.expr->accept(*this);
  };
  void visit(__attribute__((unused)) AttachPoint &ap) override { };  // Leaf
  void visit(Probe &probe) override {
    probe_ = &probe;
    for (AttachPoint *ap : *probe.attach_points) {
      ap->accept(*this);
    }
    if (probe.pred) {
      probe.pred->accept(*this);
    }
    for (Statement *stmt : *probe.stmts) {
      stmt->accept(*this);
    }
  };
  void visit(Program &program) override {
    for (Probe *probe : *program.probes)
      probe->accept(*this);
  };

  void analyse(Probe *probe) {
    probe_ = probe;
    probe->accept(*this);
  }
private:
  Probe *probe_;
};
} // namespace ast

class TracepointFormatParser
{
public:
  static bool parse(ast::Program *program);
  static std::string get_struct_name(const std::string &category, const std::string &event_name);

private:
  static std::string parse_field(const std::string &line);
  static std::string adjust_integer_types(const std::string &field_type, int size);
  static std::set<std::string> struct_list;

protected:
  static std::string get_tracepoint_struct(std::istream &format_file, const std::string &category, const std::string &event_name);
};

} // namespace bpftrace
