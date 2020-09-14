#pragma once

#include <fstream>
#include <memory>

#include "ast.h"
#include "bpftrace.h"
#include "parser.tab.hh"

typedef void* yyscan_t;
#define YY_DECL bpftrace::Parser::symbol_type yylex(bpftrace::Driver &driver, yyscan_t yyscanner)
YY_DECL;

namespace bpftrace {

class Driver
{
public:
  explicit Driver(BPFtrace &bpftrace, std::ostream &o = std::cerr);
  ~Driver();

  int parse();
  int parse_str(std::string script);
  void source(std::string, std::string);
  void error(std::ostream &, const location &, const std::string &);
  void error(const location &l, const std::string &m);
  void error(const std::string &m);
  std::unique_ptr<ast::Program> root_;

  BPFtrace &bpftrace_;

private:
  std::unique_ptr<Parser> parser_;
  std::ostream &out_;
  yyscan_t scanner_;
  bool failed_ = false;
};

} // namespace bpftrace
