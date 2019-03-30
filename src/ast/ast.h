#pragma once

#include <string>
#include <vector>
#include <map>
#include "utils.h"

#include "types.h"

namespace bpftrace {
namespace ast {

class Visitor;

class Node {
public:
  virtual ~Node() { }
  virtual void accept(Visitor &v) = 0;
};

class Map;
class Variable;
class Expression : public Node {
public:
  SizedType type;
  Map *map = nullptr; // Only set when this expression is assigned to a map
  Variable *var = nullptr; // Set when this expression is assigned to a variable
  bool is_literal = false;
  bool is_variable = false;
  bool is_map = false;
};
using ExpressionList = std::vector<Expression *>;

class Integer : public Expression {
public:
  explicit Integer(long n) : n(n) { is_literal = true; }
  long n;

  void accept(Visitor &v) override;
};

class PositionalParameter : public Expression {
public:
  explicit PositionalParameter(long n) : n(n) { is_literal = true; }
  long n;

  void accept(Visitor &v) override;
};

class String : public Expression {
public:
  explicit String(std::string str) : str(str) { is_literal = true; }
  std::string str;

  void accept(Visitor &v) override;
};

class StackMode : public Expression {
public:
  explicit StackMode(std::string mode) : mode(mode) {}
  std::string mode;

  void accept(Visitor &v) override;
};

class Identifier : public Expression {
public:
  explicit Identifier(std::string ident) : ident(ident) {}
  std::string ident;

  void accept(Visitor &v) override;
};

class Builtin : public Expression {
public:
  explicit Builtin(std::string ident) : ident(is_deprecated(ident)) {}
  std::string ident;
  int probe_id;

  void accept(Visitor &v) override;
};

class Call : public Expression {
public:
  explicit Call(std::string &func) : func(is_deprecated(func)), vargs(nullptr) { }
  Call(std::string &func, ExpressionList *vargs) : func(is_deprecated(func)), vargs(vargs) { }
  std::string func;
  ExpressionList *vargs;

  void accept(Visitor &v) override;
};

class Map : public Expression {
public:
  explicit Map(std::string &ident) : ident(ident), vargs(nullptr) { is_map = true; }
  Map(std::string &ident, ExpressionList *vargs) : ident(ident), vargs(vargs) { is_map = true; }
  std::string ident;
  ExpressionList *vargs;

  void accept(Visitor &v) override;
};

class Variable : public Expression {
public:
  explicit Variable(std::string &ident) : ident(ident) { is_variable = true; }
  std::string ident;

  void accept(Visitor &v) override;
};

class Binop : public Expression {
public:
  Binop(Expression *left, int op, Expression *right) : left(left), right(right), op(op) { }
  Expression *left, *right;
  int op;

  void accept(Visitor &v) override;
};

class Unop : public Expression {
public:
  Unop(int op, Expression *expr) : expr(expr), op(op) { }
  Expression *expr;
  int op;

  void accept(Visitor &v) override;
};

class FieldAccess : public Expression {
public:
  FieldAccess(Expression *expr, const std::string &field) : expr(expr), field(field) { }
  Expression *expr;
  std::string field;

  void accept(Visitor &v) override;
};

class ArrayAccess : public Expression {
public:
  ArrayAccess(Expression *expr, Expression* indexpr) : expr(expr), indexpr(indexpr) { }
  Expression *expr;
  Expression *indexpr;

  void accept(Visitor &v) override;
};

class Cast : public Expression {
public:
  Cast(const std::string &type, bool is_pointer, Expression *expr)
    : cast_type(type), is_pointer(is_pointer), expr(expr) { }
  std::string cast_type;
  bool is_pointer;
  Expression *expr;

  void accept(Visitor &v) override;
};

class Statement : public Node {
};
using StatementList = std::vector<Statement *>;

class ExprStatement : public Statement {
public:
  explicit ExprStatement(Expression *expr) : expr(expr) { }
  Expression *expr;

  void accept(Visitor &v) override;
};

class AssignMapStatement : public Statement {
public:
  AssignMapStatement(Map *map, Expression *expr) : map(map), expr(expr) {
    expr->map = map;
  }
  Map *map;
  Expression *expr;

  void accept(Visitor &v) override;
};

class AssignVarStatement : public Statement {
public:
  AssignVarStatement(Variable *var, Expression *expr) : var(var), expr(expr) {
    expr->var = var;
  }
  Variable *var;
  Expression *expr;

  void accept(Visitor &v) override;
};

class If : public Statement {
public:
  If(Expression *cond, StatementList *stmts) : cond(cond), stmts(stmts) { }
  If(Expression *cond, StatementList *stmts, StatementList *else_stmts)
    : cond(cond), stmts(stmts), else_stmts(else_stmts) { }
  Expression *cond;
  StatementList *stmts = nullptr;
  StatementList *else_stmts = nullptr;

  void accept(Visitor &v) override;
};

class Unroll : public Statement {
public:
  Unroll(long int var, StatementList *stmts) : var(var), stmts(stmts) {}

  long int var = 0;
  StatementList *stmts;

  void accept(Visitor &v) override;
};

class Predicate : public Node {
public:
  explicit Predicate(Expression *expr) : expr(expr) { }
  Expression *expr;

  void accept(Visitor &v) override;
};

class Ternary : public Expression {
public:
  Ternary(Expression *cond, Expression *left, Expression *right) : cond(cond), left(left), right(right) { }
  Expression *cond, *left, *right;

  void accept(Visitor &v) override;
};

class AttachPoint : public Node {
public:
  explicit AttachPoint(const std::string &provider)
    : provider(probetypeName(provider)) { }
  AttachPoint(const std::string &provider,
              const std::string &func)
    : provider(probetypeName(provider)), func(func), need_expansion(true) { }
  AttachPoint(const std::string &provider,
              const std::string &target,
              const std::string &func,
              bool need_expansion)
    : provider(probetypeName(provider)), target(target), func(func), need_expansion(need_expansion) { }
  AttachPoint(const std::string &provider,
              const std::string &target,
              const std::string &ns,
              const std::string &func,
              bool need_expansion)
    : provider(probetypeName(provider)), target(target), ns(ns), func(func), need_expansion(need_expansion) { }
  AttachPoint(const std::string &provider,
              const std::string &target,
              int freq)
    : provider(probetypeName(provider)), target(target), freq(freq), need_expansion(true) { }

  std::string provider;
  std::string target;
  std::string ns;
  std::string func;
  int freq = 0;
  bool need_expansion = false;

  void accept(Visitor &v) override;
  std::string name(const std::string &attach_point) const;

  int index(std::string name);
  void set_index(std::string name, int index);
private:
  std::map<std::string, int> index_;
};
using AttachPointList = std::vector<AttachPoint *>;

class Probe : public Node {
public:
  Probe(AttachPointList *attach_points, Predicate *pred, StatementList *stmts)
    : attach_points(attach_points), pred(pred), stmts(stmts) { }

  AttachPointList *attach_points;
  Predicate *pred;
  StatementList *stmts;

  void accept(Visitor &v) override;
  std::string name() const;
  bool need_expansion = false;	// must build a BPF program per wildcard match
  bool need_tp_args_structs = false;  // must import struct for tracepoints

  int index();
  void set_index(int index);
private:
  int index_ = 0;
};
using ProbeList = std::vector<Probe *>;

class Program : public Node {
public:
  Program(const std::string &c_definitions, ProbeList *probes)
    : c_definitions(c_definitions), probes(probes) { }
  std::string c_definitions;
  ProbeList *probes;

  void accept(Visitor &v) override;
};

class Visitor {
public:
  virtual ~Visitor() { }
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
  virtual void visit(ExprStatement &expr) = 0;
  virtual void visit(AssignMapStatement &assignment) = 0;
  virtual void visit(AssignVarStatement &assignment) = 0;
  virtual void visit(If &if_block) = 0;
  virtual void visit(Unroll &unroll) = 0;
  virtual void visit(Predicate &pred) = 0;
  virtual void visit(AttachPoint &ap) = 0;
  virtual void visit(Probe &probe) = 0;
  virtual void visit(Program &program) = 0;
};

std::string opstr(Binop &binop);
std::string opstr(Unop &unop);

} // namespace ast
} // namespace bpftrace
