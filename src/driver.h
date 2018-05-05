#pragma once

#include <memory>

#include "ast.h"
#include "parser.tab.hh"

typedef void* yyscan_t;
#define YY_DECL bpftrace::Parser::symbol_type yylex(bpftrace::Driver &driver, yyscan_t yyscanner)
YY_DECL;

namespace bpftrace {

class Driver
{
public:
  Driver();
  ~Driver();

  int parse_stdin();
  int parse_str(const std::string &script);
  int parse_file(const std::string &f);
  void error(const location &l, const std::string &m);
  void error(const std::string &m);

  ast::Program *root_;

private:
  std::unique_ptr<Parser> parser_;
  yyscan_t scanner_;
};

} // namespace bpftrace
