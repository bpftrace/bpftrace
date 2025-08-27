#pragma once

#include <optional>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/pass_manager.h"
#include "parser.tab.hh"

using yyscan_t = void *;

#define YY_DECL                                                                \
  bpftrace::Parser::symbol_type yylex(bpftrace::Driver &driver,                \
                                      yyscan_t yyscanner)

namespace bpftrace {

class Driver {
public:
  explicit Driver(ast::ASTContext &ctx, bool debug = false)
      : ctx(ctx), debug(debug) {};
  ast::Program *parse_program();
  std::optional<ast::Expression> parse_expr();

  void error(const location &l, const std::string &m);

  // These are accessible to the parser and lexer, but are not mutable.
  ast::ASTContext &ctx;
  const bool debug;

  // These are mutable state that can be modified by the lexer.
  location loc;
  std::string struct_type;
  std::string buffer;

  // This is the token injected into the lexer.
  std::optional<Parser::symbol_type> token;

  // The final result is available here.
  std::variant<ast::Program *, ast::Expression> result;

private:
  void parse(Parser::symbol_type first_token);
};

ast::Pass CreateParsePass(bool debug = false);

} // namespace bpftrace
