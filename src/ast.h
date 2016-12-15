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

class Integer : public Expression {
public:
  explicit Integer(int n) : n(n) { }
  void print_ast(std::ostream &out, unsigned int depth = 0) const override;
  int n;
};

class Identifier : public Expression {
public:
  explicit Identifier(std::string &ident) : ident(ident) { }
  void print_ast(std::ostream &out, unsigned int depth = 0) const override;
  std::string ident;
};

class Statement : public Node {
public:
  explicit Statement(Expression *expr) : expr(expr) { }
  void print_ast(std::ostream &out, unsigned int depth = 0) const override;
  Expression *expr;
};
using StatementList = std::vector<Statement *>;

class Probe : public Node {
public:
  Probe(std::string type, std::string attach_point, StatementList *stmts)
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
