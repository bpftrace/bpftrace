#pragma once

#include "ast/context.h"
#include "bpftrace.h"

typedef void *yyscan_t;

#define YY_DECL                                                                \
  bpftrace::Parser::symbol_type yylex(bpftrace::Driver &driver,                \
                                      yyscan_t yyscanner)

namespace bpftrace {

class Parser;

class Driver {
public:
  explicit Driver(ast::ASTContext &ctx, bool debug = false)
      : ctx(ctx), debug(debug) {};
  void parse();
  void error(const location &l, const std::string &m);

  // These are accessible to the parser and lexer, but are not mutable.
  ast::ASTContext &ctx;
  const bool debug;
};

} // namespace bpftrace
