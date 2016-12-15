#pragma once

#include <string>
#include <vector>
#include <ostream>

namespace ebpf {
namespace bpftrace {
namespace ast {

class Node {
public:
  virtual ~Node() { }
  virtual void print_ast(std::ostream &out, unsigned int depth = 0) const = 0;
};

class Expression : public Node {
};
using ExpressionList = std::vector<Expression *>;

class Integer : public Expression {
public:
  explicit Integer(int n) : n(n) { }
  void print_ast(std::ostream &out, unsigned int depth = 0) const override;
  int n;
};

class Variable : public Expression {
public:
  explicit Variable(std::string &ident) : ident(ident), vargs(nullptr) { }
  Variable(std::string &ident, ExpressionList *vargs) : ident(ident), vargs(vargs) { }
  void print_ast(std::ostream &out, unsigned int depth = 0) const override;
  std::string ident;
  ExpressionList *vargs;
};

class Statement : public Node {
};
using StatementList = std::vector<Statement *>;

class ExprStatement : public Statement {
public:
  explicit ExprStatement(Expression *expr) : expr(expr) { }
  void print_ast(std::ostream &out, unsigned int depth = 0) const override;
  Expression *expr;
};

class AssignStatement : public Statement {
public:
  AssignStatement(Variable *var, Expression *expr) : var(var), expr(expr) { }
  void print_ast(std::ostream &out, unsigned int depth = 0) const override;
  Variable *var;
  Expression *expr;
};

class Probe : public Node {
public:
  Probe(std::string &type, std::string &attach_point, StatementList *stmts)
    : type(type), attach_point(attach_point), stmts(stmts) { }
  void print_ast(std::ostream &out, unsigned int depth = 0) const override;

  std::string type;
  std::string attach_point;
  StatementList *stmts;
};
using ProbeList = std::vector<Probe *>;

class Program : public Node {
public:
  explicit Program(ProbeList *probes) : probes(probes) { }
  void print_ast(std::ostream &out, unsigned int depth = 0) const override;
  ProbeList *probes;
};

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
