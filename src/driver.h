#pragma once

#include "parser.tab.hh"
#include "ast.h"

#define YY_DECL ebpf::bpftrace::Parser::symbol_type yylex(ebpf::bpftrace::Driver &driver)
YY_DECL;

extern FILE *yyin;

namespace ebpf {
namespace bpftrace {

class Driver {
public:
  Driver() : parser_(*this) { }

  int parse();
  int parse(const std::string &f);
  void dump_ast(std::ostream &out);
  int analyse();
  int compile();

  void error(const location &l, const std::string &m)
  {
    std::cerr << l << ": " << m << std::endl;
  }

  void error(const std::string &m)
  {
    std::cerr << m << std::endl;
  }

  ast::Program *root_;

private:
  Parser parser_;
};

} // namespace bpftrace
} // namespace ebpf
