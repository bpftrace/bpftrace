#pragma once

#include <string>
#include <vector>

namespace ebpf {
namespace bpftrace {
namespace ast {

class Visitor;

class Node {
public:
  virtual ~Node() { }
  virtual void accept(Visitor &v) = 0;
};

class Expression : public Node {
};
using ExpressionList = std::vector<Expression *>;

class Integer : public Expression {
public:
  explicit Integer(int n) : n(n) { }
  int n;

  void accept(Visitor &v) override;
};

class Variable : public Expression {
public:
  explicit Variable(std::string &ident) : ident(ident), vargs(nullptr) { }
  Variable(std::string &ident, ExpressionList *vargs) : ident(ident), vargs(vargs) { }
  std::string ident;
  ExpressionList *vargs;

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

class Statement : public Node {
};
using StatementList = std::vector<Statement *>;

class ExprStatement : public Statement {
public:
  explicit ExprStatement(Expression *expr) : expr(expr) { }
  Expression *expr;

  void accept(Visitor &v) override;
};

class AssignStatement : public Statement {
public:
  AssignStatement(Variable *var, Expression *expr) : var(var), expr(expr) { }
  Variable *var;
  Expression *expr;

  void accept(Visitor &v) override;
};

class Probe : public Node {
public:
  Probe(std::string &type, std::string &attach_point, StatementList *stmts)
    : type(type), attach_point(attach_point), pred(nullptr), stmts(stmts) { }
  Probe(std::string &type, std::string &attach_point, Expression *pred, StatementList *stmts)
    : type(type), attach_point(attach_point), pred(pred), stmts(stmts) { }

  std::string type;
  std::string attach_point;
  Expression *pred;
  StatementList *stmts;

  void accept(Visitor &v) override;
};
using ProbeList = std::vector<Probe *>;

class Program : public Node {
public:
  explicit Program(ProbeList *probes) : probes(probes) { }
  ProbeList *probes;

  void accept(Visitor &v) override;
};

class Visitor {
public:
  virtual ~Visitor() { }
  virtual void visit(Integer &integer) = 0;
  virtual void visit(Variable &var) = 0;
  virtual void visit(Binop &binop) = 0;
  virtual void visit(Unop &unop) = 0;
  virtual void visit(ExprStatement &expr) = 0;
  virtual void visit(AssignStatement &assignment) = 0;
  virtual void visit(Probe &probe) = 0;
  virtual void visit(Program &program) = 0;

  int depth_ = 0;
};

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
