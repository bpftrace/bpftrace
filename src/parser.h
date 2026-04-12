#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/pass_manager.h"

namespace bpftrace {

ast::Pass CreateParsePass(bool debug = false);

// RD -> Recursive Descent
// N.B. the debug argument is only valid if compiled in DEBUG mode
class Parser {
public:
  explicit Parser(ast::ASTContext &ctx, bool debug = false)
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
  void skip_config_block(const std::string &err_msg);
  ast::Probe *parse_probe();
  ast::AttachPoint *parse_attach_point();
  std::optional<ast::Expression> parse_predicate();

  // Block and statement grammar
  ast::BlockExpr *parse_block(bool allow_trailing_expr = true);
  ast::Statement parse_while_or_unroll();
  ast::Statement parse_for();
  void skip_to_block_end();
  void expect_stmt_end();
  void normalize_block_expression(ast::Expression &expr);
  bool parse_sigiled_stmt_or_trailing_expr(
      ast::StatementList &stmts,
      std::optional<ast::Expression> &trailing_expr);
  std::optional<ast::Operator> try_compound_op();
  ast::Statement make_assignment(ast::Expression &lhs,
                                 ast::Expression rhs,
                                 const ast::SourceLocation &loc);
  ast::Statement make_assignment_or_expr(ast::Expression lhs,
                                         int stmt_line,
                                         int stmt_col);
  ast::Statement parse_statement();

  // Type parsing
  ast::ParsedType *parse_type(bool emit_error = true);
  ast::Typeof *parse_type_annotation(bool type_only = false);
  std::optional<size_t> scan_type_suffixes(size_t pos, bool &saw_suffix) const;
  std::optional<std::variant<ast::Expression, ast::ParsedType *>> try_parse_type_reference(
      std::string_view end_chars);

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
  std::optional<ast::Expression> try_parse_record(int begin_line,
                                                  int begin_col);
  std::optional<ast::Expression> try_parse_cast_expr(int begin_line,
                                                     int begin_col);
  ast::Expression parse_tuple_or_grouping_expr(int begin_line, int begin_col);
  ast::Expression parse_map_with_optional_keys(int begin_line, int begin_col);
  std::vector<std::string> parse_field_access();

  // Lexer helpers: peek/check (do not advance pos_)
  char at(size_t pos) const
  {
    return (*input_)[pos];
  }
  bool in_bounds(size_t pos) const
  {
    return pos < input_->size();
  }
  bool at_end() const;
  char peek(size_t offset = 0) const;
  char char_at(size_t pos) const;
  char previous_non_hspace() const;
  std::string_view view(size_t start, size_t end) const;
  std::string_view peek_keyword() const;
  bool check_keyword(const std::string &s) const;
  struct BinopInfo {
    ast::Operator op;
    int prec;
  };
  std::optional<BinopInfo> peek_binop() const;
  static bool is_hspace(char c);
  static bool is_identifier_start(char c);
  static bool is_identifier_body(char c);
  static bool is_builtin(std::string_view name);
  bool can_start_expression() const;
  bool looks_like_c_definition() const;

  // Lexer helpers: scan (take pos, return new pos, no advance pos_)
  size_t scan_layout(size_t pos) const;
  size_t scan_identifier_end(size_t pos) const;
  size_t scan_balanced(size_t pos, char open, char close) const;
  size_t scan_pointer_suffix(size_t pos) const;

  // Lexer helpers: consume (advance pos_/line_/col_)
  void advance(int n = 1);
  void consume_layout();
  void consume_line_comment();
  void consume_block_comment();
  bool match(char c);
  bool match(const std::string &s);
  bool expect(char c);
  bool expect(const std::string &s);
  std::string consume_ident_from(size_t start);
  std::optional<std::string> consume_identifier(std::string err_msg = "");
  std::string consume_variable();
  std::string consume_map();
  std::string consume_string();
  std::string consume_integer_str();

  // Error reporting
  bool has_errors() const;
  void error(const std::string &msg);
  void error(const std::string &msg,
             int begin_line,
             int begin_col,
             int end_line,
             int end_col);
  ast::None *make_none();

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

  // Saves parser position for backtracking. Call restore() to rewind.
  struct SavePoint {
    size_t pos;
    int line;
    int col;

    explicit SavePoint(Parser &p)
        : pos(p.pos_), line(p.line_), col(p.col_), parser_(p)
    {
    }
    void restore()
    {
      parser_.pos_ = pos;
      parser_.line_ = line;
      parser_.col_ = col;
    }

  private:
    Parser &parser_;
  };
  SavePoint save_point()
  {
    return SavePoint(*this);
  }

  ast::ASTContext &ctx_;
  const bool debug_;

  const std::string *input_ = nullptr;
  size_t pos_ = 0;
  int line_ = 1;
  int col_ = 1;
};

} // namespace bpftrace
