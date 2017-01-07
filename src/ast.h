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

class Builtin : public Expression {
public:
  explicit Builtin(std::string ident) : ident(ident) { }
  std::string ident;

  void accept(Visitor &v) override;
};

class Call : public Expression {
public:
  explicit Call(std::string &func) : func(func), vargs(nullptr) { }
  Call(std::string &func, ExpressionList *vargs) : func(func), vargs(vargs) { }
  std::string func;
  ExpressionList *vargs;

  void accept(Visitor &v) override;
};

class Map : public Expression {
public:
  explicit Map(std::string &ident) : ident(ident), vargs(nullptr) { }
  Map(std::string &ident, ExpressionList *vargs) : ident(ident), vargs(vargs) { }
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

class AssignMapStatement : public Statement {
public:
  AssignMapStatement(Map *map, Expression *expr) : map(map), expr(expr) { }
  Map *map;
  Expression *expr;

  void accept(Visitor &v) override;
};

class AssignMapCallStatement : public Statement {
public:
  AssignMapCallStatement(Map *map, Call *call) : map(map), call(call) { }
  Map *map;
  Call *call;

  void accept(Visitor &v) override;
};

class Predicate : public Node {
public:
  explicit Predicate(Expression *expr) : expr(expr) { }
  Expression *expr;

  void accept(Visitor &v) override;
};

class Probe : public Node {
public:
  Probe(std::string &type, std::string &attach_point, StatementList *stmts)
    : type(type), attach_point(attach_point), pred(nullptr), stmts(stmts), name(type+":"+attach_point) { }
  Probe(std::string &type, std::string &attach_point, Predicate *pred, StatementList *stmts)
    : type(type), attach_point(attach_point), pred(pred), stmts(stmts), name(type+":"+attach_point) { }

  std::string type;
  std::string attach_point;
  std::string name;
  Predicate *pred;
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
  virtual void visit(Builtin &builtin) = 0;
  virtual void visit(Call &call) = 0;
  virtual void visit(Map &map) = 0;
  virtual void visit(Binop &binop) = 0;
  virtual void visit(Unop &unop) = 0;
  virtual void visit(ExprStatement &expr) = 0;
  virtual void visit(AssignMapStatement &assignment) = 0;
  virtual void visit(AssignMapCallStatement &assignment) = 0;
  virtual void visit(Predicate &pred) = 0;
  virtual void visit(Probe &probe) = 0;
  virtual void visit(Program &program) = 0;
};

std::string opstr(Binop &binop);
std::string opstr(Unop &unop);

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
