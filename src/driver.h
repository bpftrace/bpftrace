#pragma once

#include "ast.h"
#include "parser.tab.hh"

#define YY_DECL bpftrace::Parser::symbol_type yylex(bpftrace::Driver &driver)
YY_DECL;

namespace bpftrace {

class Driver {
public:
  Driver() : parser_(*this) { }

  int parse_stdin();
  int parse_str(const std::string &script);
  int parse_file(const std::string &f);

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
