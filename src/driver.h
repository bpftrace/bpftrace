#pragma once

#include <istream>
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

  int parse()
  {
    return parser_.parse();
  }

  int parse(const std::string &f)
  {
    if (!(yyin = fopen(f.c_str(), "r"))) {
      std::cerr << "Could not open file" << std::endl;
      return -1;
    }
    return parser_.parse();
  }

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
