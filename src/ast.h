#pragma once

#include <string>
#include <vector>

namespace ebpf {
namespace bpftrace {
namespace ast {

class Node {
public:
  virtual ~Node() { }
};

class Expression : public Node {
};

class Integer : public Expression {
public:
  explicit Integer(int n) : n(n) { }
  int n;
};

class Identifier : public Expression {
public:
  explicit Identifier(std::string &ident) : ident(ident) { }
  std::string ident;
};

class Statement : public Node {
public:
  explicit Statement(Expression *expr) : expr(expr) { }
  Expression *expr;
};
using StatementList = std::vector<Statement *>;

class PreProcessor : public Node {
public:
  explicit PreProcessor(const std::string &line) : line(line) { }

  std::string line;
};
using PreProcessorList = std::vector<PreProcessor *>;

class Probe : public Node {
public:
  Probe(std::string type, std::string attach_point, StatementList *stmts)
    : type(type), attach_point(attach_point), stmts(stmts) { }

  std::string type;
  std::string attach_point;
  StatementList *stmts;
};
using ProbeList = std::vector<Probe *>;

class Program : public Node {
public:
  Program(PreProcessorList *preprocs, ProbeList *probes)
    : preprocs(preprocs), probes(probes) { }
  PreProcessorList *preprocs;
  ProbeList *probes;
};

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
