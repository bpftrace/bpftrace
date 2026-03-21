#pragma once

#include <optional>
#include <string>

#include "ast/ast.h"
#include "ast/context.h"

namespace bpftrace {

// RD -> Recursive Descent
class RDParser {
public:
  explicit RDParser(ast::ASTContext &ctx, bool debug = false)
      : ctx_(ctx), debug_(debug) {};

  ast::Program *parse();
  std::optional<ast::Expression> parse_expr();

private:
  // Root-level grammar
  ast::Program *parse_program();
  ast::CStatement *parse_c_preprocessor();
  ast::CStatement *parse_c_definition();
  ast::RootImport *parse_root_import();
  ast::StatementImport *parse_statement_import();
  ast::Macro *parse_macro();
  ast::Expression parse_macro_arg();
  ast::Subprog *parse_subprog();
  ast::MapDeclStatement *parse_map_decl_stmt();
  ast::Config *parse_config();
  ast::Probe *parse_probe();
  ast::AttachPoint *parse_attach_point();
  std::optional<ast::Expression> parse_predicate();

  // Block and statement grammar
  ast::BlockExpr *parse_block(bool allow_trailing_expr = true);
  ast::Statement parse_while_or_unroll();
  ast::Statement parse_for();
  void expect_stmt_end();
  std::optional<ast::Operator> try_compound_op();
  ast::Statement make_assignment_or_expr(ast::Expression lhs,
                                         int stmt_line,
                                         int stmt_col);
  ast::Statement parse_statement();

  // Type parsing
  SizedType parse_sized_type();
  std::optional<SizedType> try_parse_sized_type();
  ast::Typeof *parse_type_annotation();

  // Expression grammar
  ast::Expression parse_expression();
  ast::Expression parse_ternary();
  ast::Expression parse_binary(int min_prec);
  ast::Expression parse_binary(int min_prec, ast::Expression left);
  ast::Expression parse_unary();
  ast::Expression parse_postfix(ast::Expression expr);
  ast::Expression parse_primary();
  ast::Expression parse_call_expression(const std::string &name,
                                        const ast::SourceLocation &start_loc);
  ast::Expression parse_paren_expr();
  ast::Expression parse_map_with_optional_keys(int start_line, int start_col);
  std::vector<std::string> parse_field_list();

  // Lexer helpers
  void advance();
  char peek() const;
  char peek_next() const;
  bool at_end() const;
  void skip_whitespace();
  bool match(char c);
  bool match(const std::string &s);
  bool check_keyword(const std::string &s) const;
  bool expect(char c);
  std::string consume_identifier();
  std::string consume_string();
  std::string consume_integer_str();

  // Error reporting
  void error(const std::string &msg);
  void error(const std::string &msg,
             int begin_line,
             int begin_col,
             int end_line,
             int end_col);

  // Source location tracking
  ast::SourceLocation make_loc(int begin_line,
                               int begin_col,
                               int end_line,
                               int end_col) const;
  struct LineCol {
    int line;
    int col;
  };
  LineCol get_current_line_col();

  // Lookahead helpers
  static bool is_builtin(const std::string &name);
  bool looks_like_type() const;
  bool looks_like_c_definition() const;

  ast::ASTContext &ctx_;
  const bool debug_;

  const std::string *input_ = nullptr;
  size_t pos_ = 0;
  int line_ = 1;
  int col_ = 1;
};

} // namespace bpftrace
