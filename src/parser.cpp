#include "parser.h"

#include <algorithm>
#include <climits>
#include <functional>
#include <set>
#include <sstream>
#include <unordered_set>

#include "log.h"
#include "util/int_parser.h"

// clang-format off
#ifndef NDEBUG
#define PARSE_TRACE(msg)                                                       \
  do {                                                                         \
    if (debug_)                                                                \
      LOG(DEBUG) << "[parse] " << line_ << ":" << col_ << " " << msg;         \
  } while (0)
#else
#define PARSE_TRACE(msg) ((void)0)
#endif
// clang-format on

namespace bpftrace {
using namespace ast;

Program *Parser::parse()
{
  input_ = &ctx_.source_->contents;
  pos_ = 0;
  line_ = 1;
  col_ = 1;
  return parse_program();
}

// For the CMacroExpander pass
std::optional<Expression> Parser::parse_expr()
{
  input_ = &ctx_.source_->contents;
  pos_ = 0;
  line_ = 1;
  col_ = 1;
  consume_layout();
  if (at_end()) {
    return std::nullopt;
  }
  auto expr = parse_expression();
  consume_layout();
  if (!at_end()) {
    error("unexpected input");
  }
  if (ctx_.diagnostics().ok()) {
    return expr;
  }
  return std::nullopt;
}

Program *Parser::parse_program()
{
  PARSE_TRACE("parse_program");
  RootImportList imports;
  RootStatements root_stmts;
  std::optional<std::string> header;

  consume_layout();

  // Skip shebang line (e.g. "#!/usr/bin/env bpftrace")
  if (peek() == '#' && peek(1) == '!') {
    size_t header_start = pos_;
    while (!at_end() && peek() != '\n') {
      advance();
    }
    if (peek() == '\n') {
      advance();
    }
    header = input_->substr(header_start, pos_ - header_start);
    consume_layout();
  }

  // Preamble: config and imports must appear after the header but they can be
  // in any order relative to each other.
  CStatementList c_stmts;
  Config *config = nullptr;

  while (!at_end() && !has_errors()) {
    auto kw = peek_keyword();
    // Config block (at most one).
    if (kw == "config") {
      if (!config) {
        config = parse_config();
      } else {
        skip_config_block("duplicate config block");
      }
      consume_layout();
      continue;
    }
    // Root-level imports.
    if (kw == "import") {
      auto *imp = parse_root_import();
      if (imp) {
        imports.push_back(imp);
      }
      consume_layout();
      continue;
    }
    break;
  }

  // C definitions: #include, struct/union/enum definitions.
  // Must appear after config/imports but before probes/macros/functions.
  consume_layout();
  while (!at_end() && !has_errors()) {
    // C preprocessor directives: #include, #define, etc.
    if (peek() == '#' && peek(1) != '!') {
      c_stmts.push_back(parse_c_preprocessor());
      consume_layout();
      continue;
    }
    // C struct/union/enum definitions: struct Name { ... }
    auto kw = peek_keyword();
    if ((kw == "struct" || kw == "union" || kw == "enum") &&
        looks_like_c_definition()) {
      c_stmts.push_back(parse_c_definition());
      consume_layout();
      continue;
    }
    break;
  }

  // Main loop: probes, macros, functions, and map declarations.
  while (!at_end() && !has_errors()) {
    consume_layout();
    if (at_end()) {
      break;
    }
    size_t before = pos_;
    auto kw = peek_keyword();
    if (peek() == '#' && peek(1) != '!') {
      auto current_pos = get_current_line_col();
      c_stmts.push_back(parse_c_preprocessor());
      error("C definitions must appear before probes and functions",
            current_pos.line,
            current_pos.col,
            line_,
            col_);
    } else if (kw == "struct" || kw == "union" || kw == "enum") {
      if (looks_like_c_definition()) {
        auto current_pos = get_current_line_col();
        c_stmts.push_back(parse_c_definition());
        error("C definitions must appear before probes and functions",
              current_pos.line,
              current_pos.col,
              line_,
              col_);
      } else {
        // Not a C definition — treat as probe.
        auto *probe = parse_probe();
        if (probe) {
          root_stmts.emplace_back(probe);
        }
      }
    } else if (kw == "config") {
      skip_config_block("config must appear before probes and functions");
    } else if (kw == "import") {
      auto current_pos = get_current_line_col();
      match("import");
      error("root imports must appear before probes and functions",
            current_pos.line,
            current_pos.col,
            line_,
            col_);
      while (!at_end() && peek() != ';' && peek() != '\n') {
        advance();
      }
      match(';');
    } else if (kw == "macro") {
      auto *macro = parse_macro();
      if (macro) {
        root_stmts.emplace_back(macro);
      }
    } else if (kw == "fn") {
      auto *subprog = parse_subprog();
      if (subprog) {
        root_stmts.emplace_back(subprog);
      }
    } else if (kw == "let") {
      // At root level, `let @...` is a map declaration.
      size_t p = scan_layout(pos_);
      p += kw.size();
      p = scan_layout(p);
      if (char_at(p) == '@') {
        auto *map_decl = parse_map_decl_stmt();
        if (map_decl) {
          root_stmts.emplace_back(map_decl);
        }
      } else {
        error("root-level let statements need to be map declarations, e.g. let "
              "@a = hash(2);");
        advance();
      }
    } else {
      auto *probe = parse_probe();
      if (probe) {
        root_stmts.emplace_back(probe);
      }
    }
    // If nothing was consumed, skip the current character to avoid
    // an infinite loop (e.g. when parsing stdlib files that contain
    // only macros and the last token wasn't recognized).
    if (pos_ == before) {
      error("unexpected input");
      advance();
    }
    consume_layout();
  }

  auto loc = make_loc(1, 1, line_, col_);
  return ctx_.make_node<Program>(loc,
                                 std::move(c_stmts),
                                 config,
                                 std::move(imports),
                                 std::move(root_stmts),
                                 std::move(header));
}

CStatement *Parser::parse_c_preprocessor()
{
  auto [begin_line, begin_col] = get_current_line_col();
  std::string line;
  while (!at_end()) {
    char next = peek();
    if (next == '\n')
      break;
    line += next;
    advance();
  }
  // Trim trailing whitespace.
  while (!line.empty() && std::isspace(line.back())) {
    line.pop_back();
  }
  auto loc = make_loc(begin_line, begin_col, line_, col_);
  if (!at_end() && peek() == '\n') {
    advance();
  }
  return ctx_.make_node<CStatement>(loc, std::move(line));
}

CStatement *Parser::parse_c_definition()
{
  auto [begin_line, begin_col] = get_current_line_col();
  std::string def;
  // Consume keyword and name up to '{'.
  while (!at_end()) {
    char next = peek();
    if (next == '{')
      break;
    def += next;
    advance();
  }
  // Consume balanced braces, skipping comments.
  int depth = 0;
  while (!at_end()) {
    char c = peek();
    if (c == '/') {
      char next_next = peek(1);
      if (next_next == '/') {
        // Line comment: consume until newline.
        while (!at_end()) {
          char next = peek();
          if (next == '\n')
            break;
          def += next;
          advance();
        }
        continue;
      }
      if (next_next == '*') {
        // Block comment: consume until "*/".
        def += c;
        advance(); // '/'
        def += peek();
        advance(); // '*'
        while (!at_end()) {
          char next = peek();
          char next_next_b = peek(1);
          if (next == '*' && next_next_b == '/') {
            def += next;
            def += next_next_b;
            advance(); // '*'
            advance(); // '/'
            break;
          }
          def += next;
          advance();
        }
        continue;
      }
    }
    if (c == '{') {
      depth++;
    } else if (c == '}') {
      depth--;
    }
    def += c;
    advance();
    if (depth == 0) {
      break;
    }
  }
  // Trim trailing whitespace.
  while (!def.empty() && std::isspace(def.back())) {
    def.pop_back();
  }
  // Ensure trailing semicolon.
  if (!def.empty() && def.back() != ';') {
    def += ";";
  }
  // Consume optional trailing semicolon from source.
  consume_layout();
  if (!at_end() && peek() == ';') {
    advance();
  }
  auto loc = make_loc(begin_line, begin_col, line_, col_);
  return ctx_.make_node<CStatement>(loc, std::move(def));
}

Config *Parser::parse_config()
{
  PARSE_TRACE("parse_config");
  auto [begin_line, begin_col] = get_current_line_col();
  if (!expect("config") || !expect('=') || !expect('{')) {
    return nullptr;
  }

  ConfigStatementList stmts;
  consume_layout();
  while (peek() != '}' && !at_end()) {
    auto [stmt_line, stmt_col] = get_current_line_col();
    auto key = consume_identifier("expected config key");
    if (!key) {
      break;
    }
    if (!expect('=')) {
      break;
    }

    consume_layout();
    auto stmt_loc = make_loc(stmt_line, stmt_col, line_, col_);

    if (peek() == '"') {
      auto val = consume_string();
      stmt_loc = make_loc(stmt_line, stmt_col, line_, col_);
      stmts.push_back(ctx_.make_node<AssignConfigVarStatement>(stmt_loc,
                                                               std::move(*key),
                                                               std::move(val)));
    } else if (check_keyword("true") || check_keyword("false")) {
      bool val = check_keyword("true");
      if (val) {
        match("true");
      } else {
        match("false");
      }
      stmt_loc = make_loc(stmt_line, stmt_col, line_, col_);
      stmts.push_back(ctx_.make_node<AssignConfigVarStatement>(stmt_loc,
                                                               std::move(*key),
                                                               val));
    } else if (std::isdigit(peek())) {
      auto int_str = consume_integer_str();
      auto res = util::to_uint(int_str, 0);
      if (!res) {
        error("invalid integer in config");
        break;
      }
      stmt_loc = make_loc(stmt_line, stmt_col, line_, col_);
      stmts.push_back(ctx_.make_node<AssignConfigVarStatement>(
          stmt_loc, std::move(*key), static_cast<uint64_t>(*res)));
    } else {
      auto val = consume_identifier("expected string, int, boolean, or ident");
      if (val) {
        stmt_loc = make_loc(stmt_line, stmt_col, line_, col_);
        stmts.push_back(ctx_.make_node<AssignConfigVarStatement>(
            stmt_loc, std::move(*key), std::move(*val)));
      }
    }
    consume_layout();
    if (peek() != '}' && !match(';')) {
      expect(';');
      // Skip to closing '}' to avoid cascading errors.
      while (!at_end() && peek() != '}') {
        advance();
      }
      break;
    }
    match(';');
    consume_layout();
  }

  expect('}');
  auto loc = make_loc(begin_line, begin_col, line_, col_);
  return ctx_.make_node<Config>(loc, std::move(stmts));
}

void Parser::skip_config_block(const std::string &err_msg)
{
  auto current_pos = get_current_line_col();
  match("config");
  error(err_msg, current_pos.line, current_pos.col, line_, col_);

  consume_layout();
  if (!match('=')) {
    return;
  }

  consume_layout();
  if (!match('{')) {
    return;
  }

  int depth = 1;
  while (!at_end() && depth > 0) {
    char next = peek();
    if (next == '{') {
      depth++;
    } else if (next == '}') {
      depth--;
    }
    if (depth > 0) {
      advance();
    }
  }
  if (!at_end()) {
    advance(); // skip closing '}'
  }
}

RootImport *Parser::parse_root_import()
{
  PARSE_TRACE("parse_root_import");
  auto [begin_line, begin_col] = get_current_line_col();
  if (!expect("import")) {
    return nullptr;
  }

  consume_layout();
  if (peek() != '"') {
    error("expected string after 'import'");
    return nullptr;
  }
  auto path = consume_string();
  auto loc = make_loc(begin_line, begin_col, line_, col_);
  if (!match(';')) {
    error("expected ';' after import");
    return nullptr;
  }

  return ctx_.make_node<RootImport>(loc, std::move(path));
}

Macro *Parser::parse_macro()
{
  PARSE_TRACE("parse_macro");
  auto [begin_line, begin_col] = get_current_line_col();
  if (!expect("macro")) {
    return nullptr;
  }

  auto name = consume_identifier("expected macro name");
  if (!name) {
    return nullptr;
  }
  auto name_loc = make_loc(begin_line, begin_col, line_, col_);

  if (!expect('(')) {
    return nullptr;
  }

  // Parse macro arguments: $var, @map, or plain identifiers.
  ExpressionList args;
  consume_layout();
  if (peek() != ')') {
    args.push_back(parse_macro_arg());
    while (match(',')) {
      args.push_back(parse_macro_arg());
    }
  }

  if (!expect(')')) {
    return nullptr;
  }

  auto *block = parse_block();
  if (!block) {
    return nullptr;
  }

  return ctx_.make_node<Macro>(
      name_loc, std::move(*name), std::move(args), block);
}

Expression Parser::parse_macro_arg()
{
  consume_layout();
  auto [begin_line, begin_col] = get_current_line_col();

  if (peek() == '$') {
    auto var_name = consume_variable();
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *var = ctx_.make_node<Variable>(loc, var_name);
    return { var };
  }

  if (peek() == '@') {
    auto map_name = consume_map();
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *map = ctx_.make_node<Map>(loc, map_name);
    return { map };
  }

  auto ident = consume_identifier(
      "expected macro argument ($var, @map, or identifier)");
  if (!ident) {
    auto *none = make_none();
    return { none };
  }

  if (is_builtin(*ident)) {
    error("builtin '" + *ident + "' can't be used as a macro argument",
          begin_line,
          begin_col,
          line_,
          col_);
    auto *none = make_none();
    return { none };
  }
  auto loc = make_loc(begin_line, begin_col, line_, col_);
  auto *id = ctx_.make_node<Identifier>(loc, std::move(*ident));
  return { id };
}

Subprog *Parser::parse_subprog()
{
  PARSE_TRACE("parse_subprog");
  auto [begin_line, begin_col] = get_current_line_col();
  if (!expect("fn")) {
    return nullptr;
  }

  auto name = consume_identifier("expected function name");
  if (!name) {
    return nullptr;
  }
  auto name_loc = make_loc(begin_line, begin_col, line_, col_);

  if (!expect('(')) {
    return nullptr;
  }

  SubprogArgList args;
  consume_layout();
  if (peek() != ')') {
    // Parse first arg: $var : type
    while (true) {
      consume_layout();
      auto [arg_line, arg_col] = get_current_line_col();
      if (peek() != '$') {
        error("expected variable in function argument");
        break;
      }
      auto var_name = consume_variable();
      auto var_loc = make_loc(arg_line, arg_col, line_, col_);
      auto *var = ctx_.make_node<Variable>(var_loc, var_name);
      if (!expect(':')) {
        break;
      }
      auto *type = parse_type_annotation();
      if (!type) {
        break;
      }
      auto arg_loc = make_loc(arg_line, arg_col, line_, col_);
      args.push_back(ctx_.make_node<SubprogArg>(arg_loc, var, type));
      if (!match(',')) {
        break;
      }
    }
  }

  if (!expect(')')) {
    return nullptr;
  }
  if (!expect(':')) {
    return nullptr;
  }

  auto *return_type = parse_type_annotation();
  if (!return_type) {
    return nullptr;
  }

  auto *block = parse_block(false);
  if (!block) {
    return nullptr;
  }

  return ctx_.make_node<Subprog>(
      name_loc, std::move(*name), return_type, std::move(args), block);
}

MapDeclStatement *Parser::parse_map_decl_stmt()
{
  auto [begin_line, begin_col] = get_current_line_col();
  if (!expect("let")) {
    return nullptr;
  }

  consume_layout();
  if (peek() != '@') {
    error("expected '@' in map declaration");
    return nullptr;
  }
  auto map_name = consume_map();

  if (!expect('=')) {
    return nullptr;
  }

  auto type_name = consume_identifier("expected map type name");
  if (!type_name) {
    return nullptr;
  }

  if (!expect('(')) {
    return nullptr;
  }
  auto int_str = consume_integer_str();
  auto res = util::to_uint(int_str, 0);
  if (!res) {
    error("expected positive integer for map declaration max entries");
    return nullptr;
  }
  if (!expect(')')) {
    return nullptr;
  }
  match(';');
  auto loc = make_loc(begin_line, begin_col, line_, col_);

  return ctx_.make_node<MapDeclStatement>(
      loc, std::move(map_name), std::move(*type_name), *res);
}

ast::Probe *Parser::parse_probe()
{
  PARSE_TRACE("parse_probe");
  auto [begin_line, begin_col] = get_current_line_col();
  AttachPointList attach_points;

  auto *ap = parse_attach_point();
  if (!ap) {
    return nullptr;
  }
  attach_points.push_back(ap);

  // Multiple attach points separated by commas.
  while (match(',')) {
    consume_layout();
    // Allow trailing comma.
    if (peek() == '/' || peek() == '{') {
      break;
    }
    ap = parse_attach_point();
    if (!ap) {
      break;
    }
    attach_points.push_back(ap);
  }

  // The probe's location spans only the attach points (not the block).
  // Use the last attach point's end location.
  const auto &last_ap_loc = attach_points.back()->loc->current;
  auto ap_loc = make_loc(
      begin_line, begin_col, last_ap_loc.end.line, last_ap_loc.end.column);

  auto [pred_start_line, pred_start_col] = get_current_line_col();
  auto pred = parse_predicate();
  auto [pred_end_line, pred_end_col] = get_current_line_col();

  auto *block = parse_block(false);
  if (!block) {
    return nullptr;
  }

  if (pred.has_value()) {
    // Desugar predicate into: { if pred { <original block> } }
    auto pred_loc = make_loc(
        pred_start_line, pred_start_col, pred_end_line, pred_end_col);
    auto *none = ctx_.make_node<None>(pred_loc);
    auto *cond = ctx_.make_node<IfExpr>(pred_loc, pred.value(), block, none);
    block = ctx_.make_node<BlockExpr>(pred_loc, StatementList{}, cond);
  }

  return ctx_.make_node<ast::Probe>(ap_loc, std::move(attach_points), block);
}

AttachPoint *Parser::parse_attach_point()
{
  PARSE_TRACE("parse_attach_point");
  consume_layout();
  auto [begin_line, begin_col] = get_current_line_col();

  // Consume everything up to a character that ends the attach point: '{', '/',
  // ',' or unescaped whitespace that is followed by one of those characters
  std::string raw;
  while (!at_end()) {
    char c = peek();

    if (c == '{' || c == ',') {
      break;
    }

    // '/' could be a predicate start or part of a path. It's a path
    // component if we've seen a ':' in the raw text (paths appear after
    // the provider separator, e.g. uprobe:/my/program:func).
    if (c == '/' && !raw.empty() && raw.find(':') == std::string::npos) {
      // No ':' seen yet — this '/' can't be a path, it's a predicate but check
      // it's not a comment.
      char next = peek(1);
      if (next != '/' && next != '*') {
        break;
      }
    }

    if (std::isspace(c)) {
      size_t p = scan_layout(pos_);
      char after = char_at(p);
      if (after == '\0') {
        break;
      }
      if (after == '{' || after == ',' || after == '/') {
        break;
      }
      // If we hit a newline and the next non-ws char doesn't continue
      // the attach point, stop. Otherwise consume the whitespace.
      break;
    }

    // Quoted string: consume entirely (for things like uprobe:"lib":func).
    if (c == '"') {
      raw += c;
      advance();
      while (!at_end()) {
        char next = peek();
        if (next == '"')
          break;
        if (next == '\\') {
          raw += next;
          advance();
          if (!at_end()) {
            raw += peek();
            advance();
          }
          continue;
        }
        raw += next;
        advance();
      }
      if (!at_end()) {
        raw += peek(); // closing quote
        advance();
      }
      continue;
    }

    raw += c;
    advance();
  }

  if (raw.empty()) {
    error("expected attach point");
    return nullptr;
  }

  auto loc = make_loc(begin_line, begin_col, line_, col_);
  return ctx_.make_node<AttachPoint>(loc, std::move(raw), false);
}

std::optional<Expression> Parser::parse_predicate()
{
  consume_layout();
  if (peek() != '/') {
    return std::nullopt;
  }

  // Make sure this is a predicate '/' and not a comment '//' or '/*'.
  char next = peek(1);
  if (next == '/' || next == '*') {
    return std::nullopt;
  }

  advance();
  auto expr = parse_expression();

  if (!match('/')) {
    error("expected '/' to close predicate");
  }

  return expr;
}

BlockExpr *Parser::parse_block(bool allow_trailing_expr)
{
  PARSE_TRACE("parse_block");
  auto [block_line, block_col] = get_current_line_col();
  if (!expect('{')) {
    return nullptr;
  }

  StatementList stmts;
  std::optional<Expression> trailing_expr;
  consume_layout();

  while (peek() != '}' && !at_end() && !has_errors()) {
    size_t before = pos_;

    auto kw = peek_keyword();

    if (kw == "import") {
      auto *imp = parse_statement_import();
      if (imp) {
        stmts.emplace_back(imp);
      }
      consume_layout();
      continue;
    }

    if (kw == "while" || kw == "unroll") {
      auto stmt = parse_while_or_unroll();
      stmts.push_back(std::move(stmt));
      consume_layout();
      continue;
    }

    if (kw == "for") {
      auto stmt = parse_for();
      stmts.push_back(std::move(stmt));
      consume_layout();
      continue;
    }

    if (kw == "break") {
      auto [begin_line, begin_col] = get_current_line_col();
      match("break");
      expect_stmt_end();
      auto loc = make_loc(begin_line, begin_col, line_, col_);
      auto *jump = ctx_.make_node<Jump>(loc, JumpType::BREAK);
      stmts.emplace_back(jump);
      consume_layout();
      continue;
    }

    if (kw == "continue") {
      auto [begin_line, begin_col] = get_current_line_col();
      match("continue");
      expect_stmt_end();
      auto loc = make_loc(begin_line, begin_col, line_, col_);
      auto *jump = ctx_.make_node<Jump>(loc, JumpType::CONTINUE);
      stmts.emplace_back(jump);
      consume_layout();
      continue;
    }

    if (kw == "return") {
      auto [begin_line, begin_col] = get_current_line_col();
      match("return");
      consume_layout();
      char next = peek();
      if (next == ';' || next == '}') {
        expect_stmt_end();
        auto loc = make_loc(begin_line, begin_col, line_, col_);
        auto *jump = ctx_.make_node<Jump>(loc, JumpType::RETURN);
        stmts.emplace_back(jump);
      } else {
        auto expr = parse_expression();
        expect_stmt_end();
        auto loc = make_loc(begin_line, begin_col, line_, col_);
        auto *jump = ctx_.make_node<Jump>(loc,
                                          JumpType::RETURN,
                                          std::move(expr));
        stmts.emplace_back(jump);
      }
      consume_layout();
      continue;
    }
    // Discard expression: _ = expr;
    if (peek() == '_') {
      // Check if next non-ws after '_' is '='
      size_t p = scan_layout(pos_ + 1);
      if (char_at(p) == '=' && char_at(p + 1) != '=') {
        auto [begin_line, begin_col] = get_current_line_col();
        advance(); // consume '_'
        consume_layout();
        advance(); // consume '='
        auto expr = parse_expression();
        auto loc = make_loc(begin_line, begin_col, line_, col_);
        expect_stmt_end();
        auto *discard = ctx_.make_node<DiscardExpr>(loc, std::move(expr));
        stmts.emplace_back(discard);
        consume_layout();
        continue;
      }
    }
    // Check if this is a statement (assignment/let) or an expression.
    if (kw == "let") {
      auto stmt = parse_statement();
      stmts.push_back(std::move(stmt));
    } else if (peek() == '$' || peek() == '@') {
      parse_sigiled_stmt_or_trailing_expr(stmts, trailing_expr);
    } else {
      auto [begin_line, begin_col] = get_current_line_col();
      auto expr = parse_expression();
      consume_layout();

      char next = peek();
      if (next == ';') {
        advance();
        auto loc = make_loc(begin_line, begin_col, line_, col_);
        auto *expr_stmt = ctx_.make_node<ExprStatement>(loc, std::move(expr));
        stmts.emplace_back(expr_stmt);
      } else if (next == '}') {
        // No semicolon before closing brace: trailing expression.
        trailing_expr = std::move(expr);
      } else {
        auto loc = make_loc(begin_line, begin_col, line_, col_);
        auto *expr_stmt = ctx_.make_node<ExprStatement>(loc, std::move(expr));
        if (!expr_stmt->expr.is<IfExpr>() && !expr_stmt->expr.is<BlockExpr>()) {
          error("expected ';'");
        }
        stmts.emplace_back(expr_stmt);
      }
    }
    if (pos_ == before) {
      error("unexpected input in block");
      advance();
    }
    consume_layout();
  }

  if (has_errors()) {
    return nullptr;
  }
  if (!expect('}')) {
    return nullptr;
  }

  auto loc = make_loc(block_line, block_col, line_, col_);

  if (trailing_expr && allow_trailing_expr) {
    return ctx_.make_node<BlockExpr>(loc,
                                     std::move(stmts),
                                     std::move(*trailing_expr));
  }
  if (trailing_expr) {
    // Normalize nested block expressions before converting to statement.
    normalize_block_expression(*trailing_expr);
    // Convert trailing expression to a statement (none_block semantics).
    auto *expr_stmt = ctx_.make_node<ExprStatement>(loc,
                                                    std::move(*trailing_expr));
    stmts.emplace_back(expr_stmt);
  }
  auto *none = ctx_.make_node<None>(loc);
  return ctx_.make_node<BlockExpr>(loc, std::move(stmts), Expression(none));
}

void Parser::normalize_block_expression(Expression &expr)
{
  if (auto *block = expr.as<BlockExpr>()) {
    for (auto &stmt : block->stmts) {
      if (auto *expr_stmt = stmt.as<ExprStatement>()) {
        normalize_block_expression(expr_stmt->expr);
      }
    }

    if (!block->expr.as<None>()) {
      normalize_block_expression(block->expr);
      auto *expr_stmt = ctx_.make_node<ExprStatement>(block->loc,
                                                      std::move(block->expr));
      block->stmts.emplace_back(expr_stmt);
      auto *none = ctx_.make_node<None>(block->loc);
      block->expr = Expression(none);
    }
  }

  if (auto *if_expr = expr.as<IfExpr>()) {
    normalize_block_expression(if_expr->left);
    normalize_block_expression(if_expr->right);
  }
}

bool Parser::parse_sigiled_stmt_or_trailing_expr(
    StatementList &stmts,
    std::optional<Expression> &trailing_expr)
{
  auto stmt_begin = save_point();
  size_t errors_before = ctx_.diagnostics().error_count();
  auto stmt = parse_statement();
  auto stmt_end = save_point();
  consume_layout();

  auto *expr_stmt = stmt.as<ExprStatement>();
  if (!expr_stmt) {
    stmts.push_back(std::move(stmt));
    return true;
  }

  if (ctx_.diagnostics().error_count() > errors_before) {
    stmts.push_back(std::move(stmt));
    return true;
  }

  if (peek() == ';') {
    advance();
    stmts.push_back(std::move(stmt));
    return true;
  }

  if (peek() == '}') {
    stmt_begin.restore();
    auto expr = parse_expression();
    consume_layout();
    if (peek() == '}') {
      trailing_expr = std::move(expr);
      return true;
    }

    stmt_end.restore();
    stmts.push_back(std::move(stmt));
    return true;
  }

  error("expected ';'");
  stmts.push_back(std::move(stmt));
  return true;
}

StatementImport *Parser::parse_statement_import()
{
  auto [begin_line, begin_col] = get_current_line_col();
  if (!expect("import")) {
    return nullptr;
  }

  consume_layout();
  if (peek() != '"') {
    error("expected string after 'import'");
    return nullptr;
  }
  auto path = consume_string();
  auto loc = make_loc(begin_line, begin_col, line_, col_);
  if (!match(';')) {
    error("expected ';' after import");
    return nullptr;
  }

  return ctx_.make_node<StatementImport>(loc, std::move(path));
}

Statement Parser::parse_while_or_unroll()
{
  auto [begin_line, begin_col] = get_current_line_col();
  bool is_while = check_keyword("while");
  if (is_while) {
    match("while");
  } else {
    match("unroll");
  }

  // When the condition is parenthesized, consume the parens explicitly and
  // parse a full expression inside. This prevents the paren content from
  // being misinterpreted as a record (e.g. `while(x=1, y=2)` matching the
  // `ident=expr` record pattern).
  // Without parens, parse as a unary expression so that the opening '{' of
  // the block is not consumed as part of a binary expression.
  Expression cond;
  consume_layout();
  if (peek() == '(') {
    advance(); // consume '('
    cond = parse_expression();
    expect(')');
  } else {
    cond = parse_unary();
  }
  auto *block = parse_block(false);
  auto loc = make_loc(begin_line, begin_col, line_, col_);

  if (is_while) {
    auto *w = ctx_.make_node<While>(loc, std::move(cond), block);
    return { w };
  }
  auto *u = ctx_.make_node<Unroll>(loc, std::move(cond), block);
  return { u };
}

Statement Parser::parse_for()
{
  auto [begin_line, begin_col] = get_current_line_col();
  match("for");

  bool has_open_paren = match('(');

  consume_layout();
  if (peek() != '$') {
    error("expected variable in for loop");
    skip_to_block_end();
    auto *none = make_none();
    auto *es = ctx_.make_node<ExprStatement>(none->loc, Expression(none));
    return { es };
  }
  auto [var_line, var_col] = get_current_line_col();
  auto var_name = consume_variable();
  auto var_loc = make_loc(var_line, var_col, line_, col_);
  auto *var = ctx_.make_node<Variable>(var_loc, var_name);

  if (!expect(':')) {
    skip_to_block_end();
    auto *none = make_none();
    auto *es = ctx_.make_node<ExprStatement>(none->loc, Expression(none));
    return { es };
  }

  consume_layout();

  auto first = parse_primary();
  consume_layout();

  // Check for range: first..end
  if (peek() == '.' && peek(1) == '.') {
    advance(2);
    auto end = parse_primary();
    auto range_loc = make_loc(begin_line, begin_col, line_, col_);
    auto *range = ctx_.make_node<Range>(range_loc,
                                        std::move(first),
                                        std::move(end));
    if (has_open_paren && !expect(')')) {
      skip_to_block_end();
      auto *none = make_none();
      auto *es = ctx_.make_node<ExprStatement>(none->loc, Expression(none));
      return { es };
    }
    auto *block = parse_block(false);
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *f = ctx_.make_node<For>(loc, var, range, block);
    return { f };
  }

  // Must be a map.
  if (has_open_paren && !expect(')')) {
    skip_to_block_end();
    auto *none = make_none();
    auto *es = ctx_.make_node<ExprStatement>(none->loc, Expression(none));
    return { es };
  }

  auto *map_ptr = first.as<Map>();
  if (!map_ptr) {
    error("expected map or range in for loop");
    skip_to_block_end();
    auto *none = make_none();
    auto *es = ctx_.make_node<ExprStatement>(none->loc, Expression(none));
    return { es };
  }

  auto *block = parse_block(false);
  auto loc = make_loc(begin_line, begin_col, line_, col_);
  auto *f = ctx_.make_node<For>(loc, var, map_ptr, block);
  return { f };
}

void Parser::skip_to_block_end()
{
  // Skip past a closing ')' if present, then skip the block '{...}'.
  // This is used for error recovery in for/while loops to avoid cascading
  // errors from unconsumed tokens.
  while (!at_end()) {
    char next = peek();
    if (next == '{' || next == '}') {
      break;
    }
    advance();
  }
  if (!at_end() && peek() == '{') {
    advance();
    int depth = 1;
    while (!at_end() && depth > 0) {
      char next = peek();
      if (next == '{') {
        depth++;
      } else if (next == '}') {
        depth--;
      }
      advance();
    }
  }
}

void Parser::expect_stmt_end()
{
  consume_layout();
  if (peek() != '}') {
    expect(';');
  } else {
    match(';');
  }
}

// Try to match a compound assignment operator.
std::optional<Operator> Parser::try_compound_op()
{
  consume_layout();
  if (at_end()) {
    return std::nullopt;
  }

  char c = peek();
  char next = peek(1);

  // Three-char operators
  if (c == '<' && next == '<' && peek(2) == '=') {
    advance(3);
    return Operator::LEFT;
  }
  if (c == '>' && next == '>' && peek(2) == '=') {
    advance(3);
    return Operator::RIGHT;
  }

  // Two-char operators
  if (next == '=') {
    switch (c) {
      case '+':
        advance(2);
        return Operator::PLUS;
      case '-':
        advance(2);
        return Operator::MINUS;
      case '*':
        advance(2);
        return Operator::MUL;
      case '/':
        advance(2);
        return Operator::DIV;
      case '%':
        advance(2);
        return Operator::MOD;
      case '&':
        advance(2);
        return Operator::BAND;
      case '|':
        advance(2);
        return Operator::BOR;
      case '^':
        advance(2);
        return Operator::BXOR;
      default:
        break;
    }
  }

  return std::nullopt;
}

Statement Parser::make_assignment(Expression &lhs,
                                  Expression rhs,
                                  const SourceLocation &loc)
{
  auto *map = lhs.as<Map>();
  if (map) {
    auto *assign = ctx_.make_node<AssignScalarMapStatement>(loc,
                                                            map,
                                                            std::move(rhs));
    return { assign };
  }

  auto *map_access = lhs.as<MapAccess>();
  if (map_access) {
    auto *assign = ctx_.make_node<AssignMapStatement>(loc,
                                                      map_access,
                                                      std::move(rhs));
    return { assign };
  }

  auto *var = lhs.as<Variable>();
  auto *assign = ctx_.make_node<AssignVarStatement>(loc, var, std::move(rhs));
  return { assign };
}

Statement Parser::make_assignment_or_expr(Expression lhs,
                                          int stmt_line,
                                          int stmt_col)
{
  consume_layout();

  // Simple assignment: lhs = expr
  char next = peek();
  if (next == '=' && peek(1) != '=') {
    advance();
    auto rhs = parse_expression();
    auto loc = make_loc(stmt_line, stmt_col, line_, col_);
    expect_stmt_end();
    return make_assignment(lhs, std::move(rhs), loc);
  }

  // Compound assignment: lhs += expr etc.
  {
    auto sp = save_point();
    auto compound = try_compound_op();
    if (compound) {
      auto rhs = parse_expression();
      auto op_loc = make_loc(sp.line, sp.col, line_, col_);
      auto *binop = ctx_.make_node<Binop>(
          op_loc, lhs, *compound, std::move(rhs));
      auto loc = make_loc(stmt_line, stmt_col, line_, col_);
      expect_stmt_end();
      return make_assignment(lhs, Expression(binop), loc);
    }
    sp.restore();
  }

  // Post-increment or Post-decrement
  next = peek();
  auto is_post_increment = next == '+' && peek(1) == '+';
  auto is_post_decrement = next == '-' && peek(1) == '-';
  if (is_post_increment || is_post_decrement) {
    advance(2);
    auto loc = make_loc(stmt_line, stmt_col, line_, col_);
    auto *unop = ctx_.make_node<Unop>(loc,
                                      std::move(lhs),
                                      is_post_increment
                                          ? Operator::POST_INCREMENT
                                          : Operator::POST_DECREMENT);
    auto *es = ctx_.make_node<ExprStatement>(loc, Expression(unop));
    return { es };
  }

  // Not an assignment, treat as expression statement.
  // First apply postfix operators (e.g. $x[0], $x.field), then continue
  // parsing any remaining binary operators (e.g. $x[0] == 102).
  auto postfix = parse_postfix(std::move(lhs));

  consume_layout();
  next = peek();
  if (next == '=' && peek(1) != '=') {
    // Tuple and record fields are immutable.
    if (postfix.as<TupleAccess>() || postfix.as<FieldAccess>()) {
      advance();
      parse_expression();
      auto loc = make_loc(stmt_line, stmt_col, line_, col_);
      error("Tuples and records are immutable once created. "
            "Consider creating a new value and assigning it instead.",
            stmt_line,
            stmt_col,
            loc.end.line,
            loc.end.column);
      auto *none = make_none();
      auto *es = ctx_.make_node<ExprStatement>(none->loc, Expression(none));
      return { es };
    }
    advance();
    auto rhs = parse_expression();
    auto loc = make_loc(stmt_line, stmt_col, line_, col_);
    match(';');
    auto *var = postfix.as<Variable>();
    if (var) {
      auto *assign = ctx_.make_node<AssignVarStatement>(loc,
                                                        var,
                                                        std::move(rhs));
      return { assign };
    }
    // Assignment to an invalid target (not a variable, map, or map access).
    error("invalid assignment target",
          stmt_line,
          stmt_col,
          loc.end.line,
          loc.end.column);
    auto *none = make_none();
    auto *es = ctx_.make_node<ExprStatement>(none->loc, Expression(none));
    return { es };
  }
  // Continue parsing as a full expression (binary ops, ternary, etc.).
  auto expr = parse_binary(0, std::move(postfix));
  auto loc = make_loc(stmt_line, stmt_col, line_, col_);
  auto *expr_stmt = ctx_.make_node<ExprStatement>(loc, std::move(expr));
  return { expr_stmt };
}

Statement Parser::parse_statement()
{
  PARSE_TRACE("parse_statement");
  auto [stmt_line, stmt_col] = get_current_line_col();
  consume_layout();

  // Let statement: let $x; let $x = expr; let $x : type = expr;
  if (match("let")) {
    consume_layout();
    if (peek() != '$') {
      error("expected variable after 'let'");
      auto *none = make_none();
      auto *expr_stmt = ctx_.make_node<ExprStatement>(none->loc,
                                                      Expression(none));
      return { expr_stmt };
    }
    auto [var_line, var_col] = get_current_line_col();
    auto var_name = consume_variable();
    auto var_loc = make_loc(var_line, var_col, line_, col_);
    auto *var = ctx_.make_node<Variable>(var_loc, var_name);
    // The declaration location spans from 'let' through the variable name.
    auto decl_loc = make_loc(stmt_line, stmt_col, line_, col_);

    // Check for optional type annotation.
    Typeof *type_annotation = nullptr;
    consume_layout();
    if (peek() == ':') {
      advance();
      type_annotation = parse_type_annotation();
    }

    consume_layout();
    if (peek() == '=') {
      // let $x = expr; or let $x : type = expr;
      advance();
      auto rhs = parse_expression();
      auto loc = make_loc(stmt_line, stmt_col, line_, col_);
      expect_stmt_end();
      VarDeclStatement *decl;
      if (type_annotation) {
        decl = ctx_.make_node<VarDeclStatement>(decl_loc, var, type_annotation);
      } else {
        decl = ctx_.make_node<VarDeclStatement>(decl_loc, var);
      }
      auto *assign = ctx_.make_node<AssignVarStatement>(loc,
                                                        decl,
                                                        std::move(rhs));
      return { assign };
    }

    // let $x; or let $x : type;
    auto loc = make_loc(stmt_line, stmt_col, line_, col_);
    expect_stmt_end();
    VarDeclStatement *decl;
    if (type_annotation) {
      decl = ctx_.make_node<VarDeclStatement>(decl_loc, var, type_annotation);
    } else {
      decl = ctx_.make_node<VarDeclStatement>(decl_loc, var);
    }
    return { decl };
  }

  // Variable: $x = expr; or $x += expr; or $x++ etc.
  if (peek() == '$') {
    // Check for positional parameter ($N) or param count ($#).
    if (std::isdigit(static_cast<unsigned char>(peek(1))) || peek(1) == '#') {
      // Not a variable — fall through to expression parsing.
      auto expr = parse_expression();
      auto loc = make_loc(stmt_line, stmt_col, line_, col_);
      auto *expr_stmt = ctx_.make_node<ExprStatement>(loc, std::move(expr));
      return { expr_stmt };
    }
    auto [var_line, var_col] = get_current_line_col();
    auto var_name = consume_variable();
    auto var_loc = make_loc(var_line, var_col, line_, col_);
    auto *var = ctx_.make_node<Variable>(var_loc, var_name);
    return make_assignment_or_expr(Expression(var), stmt_line, stmt_col);
  }

  // Map: @x = expr; or @x[key] = expr; or @x += expr; etc.
  if (peek() == '@') {
    auto [map_line, map_col] = get_current_line_col();
    auto map_expr = parse_map_with_optional_keys(map_line, map_col);
    return make_assignment_or_expr(std::move(map_expr), stmt_line, stmt_col);
  }

  auto expr = parse_expression();
  auto loc = make_loc(stmt_line, stmt_col, line_, col_);
  auto *expr_stmt = ctx_.make_node<ExprStatement>(loc, std::move(expr));
  return { expr_stmt };
}

// Type parsing

SizedType Parser::parse_sized_type()
{
  auto name = consume_identifier("expected type name");
  if (!name) {
    return CreateNone();
  }

  std::string type_ident = *name;
  if (*name == "struct" || *name == "union" || *name == "enum") {
    auto type_name = consume_identifier("expected identifier");
    if (!type_name) {
      return CreateNone();
    }
    type_ident += " " + *type_name;
  }
  SizedType stype = compound_ident_to_type(type_ident);

  // Pointer and array suffixes in any order.
  consume_layout();
  while (peek() == '*' || peek() == '[') {
    if (peek() == '*') {
      advance();
      stype = CreatePointer(stype);
      consume_layout();
    } else {
      advance();
      consume_layout();
      uint64_t size = 0;
      if (peek() != ']') {
        auto int_str = consume_integer_str();
        auto res = util::to_uint(int_str, 0);
        size = res ? *res : 0;
      }
      expect(']');
      stype = CreateArray(size, stype);
      consume_layout();
    }
  }

  return stype;
}

std::optional<size_t> Parser::scan_type_suffixes(size_t pos,
                                                 bool &saw_suffix) const
{
  pos = scan_layout(pos);

  while (true) {
    if (char_at(pos) == '*') {
      saw_suffix = true;
      pos = scan_pointer_suffix(pos);
      continue;
    }

    if (char_at(pos) == '[') {
      saw_suffix = true;
      size_t after = scan_balanced(pos, '[', ']');
      if (after == pos || char_at(after - 1) != ']') {
        return std::nullopt;
      }
      pos = scan_layout(after);
      continue;
    }

    break;
  }

  return pos;
}

std::optional<std::variant<Expression, SizedType>> Parser::
    try_parse_type_reference(std::string_view end_chars)
{
  auto sp = save_point();
  consume_layout();
  if (!is_identifier_start(peek())) {
    sp.restore();
    return std::nullopt;
  }

  size_t lookahead = pos_;
  const size_t ident_start = lookahead;
  lookahead = scan_identifier_end(lookahead);
  const auto ident = view(ident_start, lookahead);

  if (is_builtin(ident)) {
    sp.restore();
    return std::nullopt;
  }

  auto matches_terminator = [&](size_t end_pos) {
    char next = char_at(scan_layout(end_pos));
    return next != '\0' && end_chars.find(next) != std::string_view::npos;
  };

  bool is_known_type = false;
  if (ident == "struct" || ident == "union" || ident == "enum") {
    lookahead = scan_layout(lookahead);
    if (!is_identifier_start(char_at(lookahead))) {
      sp.restore();
      return std::nullopt;
    }
    lookahead = scan_identifier_end(lookahead);
    is_known_type = true;
  } else if (ident_to_type(std::string(ident)).has_value()) {
    is_known_type = true;
  }

  bool saw_suffix = false;
  auto end_pos = scan_type_suffixes(lookahead, saw_suffix);
  if (!end_pos || !matches_terminator(*end_pos)) {
    sp.restore();
    return std::nullopt;
  }
  bool parse_as_sized_type = is_known_type || saw_suffix;

  if (parse_as_sized_type) {
    return parse_sized_type();
  }

  auto [begin_line, begin_col] = get_current_line_col();
  auto parsed_ident = consume_identifier();
  if (!parsed_ident) {
    sp.restore();
    return std::nullopt;
  }
  auto loc = make_loc(begin_line, begin_col, line_, col_);
  auto *id = ctx_.make_node<Identifier>(loc, std::move(*parsed_ident));
  return Expression(id);
}

Typeof *Parser::parse_type_annotation()
{
  consume_layout();
  auto [begin_line, begin_col] = get_current_line_col();

  // typeof(expr_or_type)
  if (check_keyword("typeof")) {
    match("typeof");
    expect('(');
    consume_layout();

    if (auto type_ref = try_parse_type_reference(")")) {
      expect(')');
      auto loc = make_loc(begin_line, begin_col, line_, col_);
      if (auto *stype = std::get_if<SizedType>(&*type_ref)) {
        return ctx_.make_node<Typeof>(loc,
                                      normalize_array_to_sized_type(*stype));
      }
      return ctx_.make_node<Typeof>(loc,
                                    std::move(std::get<Expression>(*type_ref)));
    }
    auto expr = parse_expression();
    expect(')');
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    return ctx_.make_node<Typeof>(loc, std::move(expr));
  }

  if (auto type_ref = try_parse_type_reference(";,=){}")) {
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    if (auto *stype = std::get_if<SizedType>(&*type_ref)) {
      return ctx_.make_node<Typeof>(loc, normalize_array_to_sized_type(*stype));
    }
    return ctx_.make_node<Typeof>(loc,
                                  std::move(std::get<Expression>(*type_ref)));
  }

  // Not a type — parse as expression.
  auto expr = parse_expression();
  auto loc = make_loc(begin_line, begin_col, line_, col_);
  return ctx_.make_node<Typeof>(loc, std::move(expr));
}

// Expression grammar

// Entry point for parsing any expression. Ternary is currently the
// lowest-precedence operator, but this wrapper keeps callers insulated
// if the grammar changes.
Expression Parser::parse_expression()
{
  PARSE_TRACE("parse_expression");
  return parse_ternary();
}

// Ternary: expr ? expr : expr  or  expr ? : expr
Expression Parser::parse_ternary()
{
  PARSE_TRACE("parse_ternary");
  auto expr = parse_binary(0);
  auto sp = save_point();
  consume_layout();

  if (peek() != '?') {
    sp.restore();
    return expr;
  }

  const auto &expr_begin = expr.loc()->current.begin;
  advance();
  consume_layout();

  Expression then_expr;
  if (peek() == ':') {
    // Short form: expr ?: expr
    advance();
    auto else_expr = parse_ternary();
    auto loc = make_loc(expr_begin.line, expr_begin.column, line_, col_);
    auto *if_node = ctx_.make_node<IfExpr>(
        loc, expr, expr, std::move(else_expr));
    return { if_node };
  }

  then_expr = parse_ternary();
  expect(':');
  auto else_expr = parse_ternary();
  auto loc = make_loc(expr_begin.line, expr_begin.column, line_, col_);
  auto *if_node = ctx_.make_node<IfExpr>(
      loc, expr, std::move(then_expr), std::move(else_expr));
  return { if_node };
}

namespace {

enum class BinopPrecedence : int {
  LogicalOr = 1,
  LogicalAnd,
  BitwiseOr,
  BitwiseXor,
  BitwiseAnd,
  Equality,
  Relational,
  Shift,
  Additive,
  Multiplicative,
};

constexpr int prec(BinopPrecedence precedence)
{
  return static_cast<int>(precedence);
}

int op_length(Operator op)
{
  switch (op) {
    case Operator::LOR:
    case Operator::LAND:
    case Operator::EQ:
    case Operator::NE:
    case Operator::LE:
    case Operator::GE:
    case Operator::LEFT:
    case Operator::RIGHT:
      return 2;
    default:
      return 1;
  }
}

} // namespace

// Returns the operator and precedence for a binary operator token,
// or std::nullopt if the current position is not a binary operator.
std::optional<Parser::BinopInfo> Parser::peek_binop() const
{
  char c = peek();
  if (c == '\0') {
    return std::nullopt;
  }

  char next = peek(1);

  // Skip compound assignments — they are not binary ops in expression context.
  if (next == '=' && (c == '+' || c == '-' || c == '*' || c == '/' ||
                      c == '%' || c == '&' || c == '|' || c == '^')) {
    return std::nullopt;
  }
  // <<= and >>=
  if ((c == '<' && next == '<') || (c == '>' && next == '>')) {
    if (peek(2) == '=') {
      return std::nullopt;
    }
  }

  // Two-character operators first.
  if (c == '|' && next == '|') {
    return BinopInfo{ .op = Operator::LOR,
                      .prec = prec(BinopPrecedence::LogicalOr) };
  }
  if (c == '&' && next == '&') {
    return BinopInfo{ .op = Operator::LAND,
                      .prec = prec(BinopPrecedence::LogicalAnd) };
  }
  if (c == '=' && next == '=') {
    return BinopInfo{ .op = Operator::EQ,
                      .prec = prec(BinopPrecedence::Equality) };
  }
  if (c == '!' && next == '=') {
    return BinopInfo{ .op = Operator::NE,
                      .prec = prec(BinopPrecedence::Equality) };
  }
  if (c == '<' && next == '=') {
    return BinopInfo{ .op = Operator::LE,
                      .prec = prec(BinopPrecedence::Relational) };
  }
  if (c == '>' && next == '=') {
    return BinopInfo{ .op = Operator::GE,
                      .prec = prec(BinopPrecedence::Relational) };
  }
  if (c == '<' && next == '<') {
    return BinopInfo{ .op = Operator::LEFT,
                      .prec = prec(BinopPrecedence::Shift) };
  }
  if (c == '>' && next == '>') {
    return BinopInfo{ .op = Operator::RIGHT,
                      .prec = prec(BinopPrecedence::Shift) };
  }

  // Single-character operators.
  if (c == '|' && next != '|') {
    return BinopInfo{ .op = Operator::BOR,
                      .prec = prec(BinopPrecedence::BitwiseOr) };
  }
  if (c == '^') {
    return BinopInfo{ .op = Operator::BXOR,
                      .prec = prec(BinopPrecedence::BitwiseXor) };
  }
  if (c == '&' && next != '&') {
    return BinopInfo{ .op = Operator::BAND,
                      .prec = prec(BinopPrecedence::BitwiseAnd) };
  }
  if (c == '<' && next != '<' && next != '=') {
    return BinopInfo{ .op = Operator::LT,
                      .prec = prec(BinopPrecedence::Relational) };
  }
  if (c == '>' && next != '>' && next != '=') {
    return BinopInfo{ .op = Operator::GT,
                      .prec = prec(BinopPrecedence::Relational) };
  }
  if (c == '+' && next != '+') {
    return BinopInfo{ .op = Operator::PLUS,
                      .prec = prec(BinopPrecedence::Additive) };
  }
  if (c == '-' && next != '-') {
    return BinopInfo{ .op = Operator::MINUS,
                      .prec = prec(BinopPrecedence::Additive) };
  }
  if (c == '*') {
    return BinopInfo{ .op = Operator::MUL,
                      .prec = prec(BinopPrecedence::Multiplicative) };
  }
  if (c == '/') {
    // If '/' is followed (after whitespace) by '{', it's the end of a
    // predicate, not a division operator
    size_t p = scan_layout(pos_ + 1);
    if (char_at(p) == '{') {
      return std::nullopt;
    }
    return BinopInfo{ .op = Operator::DIV,
                      .prec = prec(BinopPrecedence::Multiplicative) };
  }
  if (c == '%') {
    return BinopInfo{ .op = Operator::MOD,
                      .prec = prec(BinopPrecedence::Multiplicative) };
  }

  return std::nullopt;
}

// Precedence-climbing binary expression parser.
Expression Parser::parse_binary(int min_prec)
{
  PARSE_TRACE("parse_binary min_prec=" << min_prec);
  return parse_binary(min_prec, parse_unary());
}

Expression Parser::parse_binary(int min_prec, Expression left)
{
  while (true) {
    auto sp = save_point();
    consume_layout();
    auto info = peek_binop();
    if (!info || info->prec < min_prec) {
      sp.restore();
      break;
    }

    const auto &left_begin = left.loc()->current.begin;
    int len = op_length(info->op);
    for (int i = 0; i < len; i++) {
      advance();
    }

    auto right = parse_binary(info->prec + 1);
    auto loc = make_loc(left_begin.line, left_begin.column, line_, col_);
    auto *binop = ctx_.make_node<Binop>(
        loc, std::move(left), info->op, std::move(right));
    left = Expression(binop);
  }

  return left;
}

// Unary prefix expressions: *expr, -expr, !expr, ~expr, ++$var, --$var
Expression Parser::parse_unary()
{
  PARSE_TRACE("parse_unary");
  consume_layout();
  auto [begin_line, begin_col] = get_current_line_col();

  // Pre-increment or -decrement: ++$var or ++@map / --$var or --@map
  auto is_pre_increment = peek() == '+' && peek(1) == '+';
  auto is_pre_decrement = peek() == '-' && peek(1) == '-';
  if (is_pre_increment || is_pre_decrement) {
    advance(2);
    auto expr = parse_unary();
    if (!expr.as<Variable>() && !expr.as<Map>() && !expr.as<MapAccess>()) {
      error("increment/decrement requires a variable or map",
            expr.loc()->current.begin.line,
            expr.loc()->current.begin.column,
            expr.loc()->current.end.line,
            expr.loc()->current.end.column);
    }
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *unop = ctx_.make_node<Unop>(loc,
                                      std::move(expr),
                                      is_pre_increment
                                          ? Operator::PRE_INCREMENT
                                          : Operator::PRE_DECREMENT);
    return { unop };
  }

  // Address-of: &$var or &@map
  if (peek() == '&') {
    advance();
    consume_layout();
    if (peek() == '$') {
      auto [var_line, var_col] = get_current_line_col();
      auto var_name = consume_variable();
      auto var_loc = make_loc(var_line, var_col, line_, col_);
      auto *var = ctx_.make_node<Variable>(var_loc, var_name);
      auto loc = make_loc(begin_line, begin_col, line_, col_);
      auto *addr = ctx_.make_node<VariableAddr>(loc, var);
      return { addr };
    }
    if (peek() == '@') {
      auto [map_line, map_col] = get_current_line_col();
      auto map_name = consume_map();
      auto map_loc = make_loc(map_line, map_col, line_, col_);
      auto *map = ctx_.make_node<Map>(map_loc, map_name);
      auto loc = make_loc(begin_line, begin_col, line_, col_);
      auto *addr = ctx_.make_node<MapAddr>(loc, map);
      return { addr };
    }
    error("address-of operator (&) can only be used on a map or variable");
    auto expr = parse_unary();
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *unop = ctx_.make_node<Unop>(loc, std::move(expr), Operator::BAND);
    return { unop };
  }

  Operator op;
  char next = peek();
  if (next == '*') {
    op = Operator::MUL;
  } else if (next == '!' && peek(1) != '=') {
    op = Operator::LNOT;
  } else if (next == '~') {
    op = Operator::BNOT;
  } else if (next == '-' && peek(1) != '-') {
    op = Operator::MINUS;
  } else {
    return parse_postfix(parse_primary());
  }

  advance();
  auto expr = parse_unary();
  auto loc = make_loc(begin_line, begin_col, line_, col_);
  auto *unop = ctx_.make_node<Unop>(loc, std::move(expr), op);
  return { unop };
}

// Postfix operations: .field, ->field, .N (tuple), [expr], ++, --
Expression Parser::parse_postfix(Expression expr)
{
  PARSE_TRACE("parse_postfix");
  while (true) {
    // Save position before whitespace lookahead so we don't advance
    // past the end of the expression when no postfix op is found.
    auto sp = save_point();
    consume_layout();
    const auto &expr_begin = expr.loc()->current.begin;

    // Field access: expr.field or tuple access: expr.N
    char next = peek();
    if (next == '.') {
      // Make sure it's not '..' (range operator)
      if (peek(1) == '.') {
        break;
      }
      advance();
      consume_layout();

      // Tuple access: expr.N
      if (std::isdigit(peek())) {
        auto int_str = consume_integer_str();
        auto res = util::to_uint(int_str, 0);
        auto loc = make_loc(expr_begin.line, expr_begin.column, line_, col_);
        auto *ta = ctx_.make_node<TupleAccess>(
            loc, std::move(expr), static_cast<ssize_t>(res ? *res : 0));
        expr = Expression(ta);
        continue;
      }

      // Field access: expr.field
      auto field = consume_identifier("expected field name after '.'");
      if (!field) {
        break;
      }
      auto loc = make_loc(expr_begin.line, expr_begin.column, line_, col_);
      auto *fa = ctx_.make_node<FieldAccess>(loc,
                                             std::move(expr),
                                             std::move(*field));
      expr = Expression(fa);
      continue;
    }

    // Arrow access: expr->field
    if (next == '-' && peek(1) == '>') {
      advance(2);
      auto field = consume_identifier("expected field name after '->'");
      if (!field) {
        break;
      }
      auto loc = make_loc(expr_begin.line, expr_begin.column, line_, col_);
      auto *fa = ctx_.make_node<FieldAccess>(loc,
                                             std::move(expr),
                                             std::move(*field));
      expr = Expression(fa);
      continue;
    }

    // Array access: expr[index]
    if (next == '[') {
      advance();
      auto index = parse_expression();
      expect(']');
      auto loc = make_loc(expr_begin.line, expr_begin.column, line_, col_);
      auto *aa = ctx_.make_node<ArrayAccess>(loc,
                                             std::move(expr),
                                             std::move(index));
      expr = Expression(aa);
      continue;
    }

    // Post-increment/decrement: expr++ / expr--
    auto is_post_increment = next == '+' && peek(1) == '+';
    auto is_post_decrement = next == '-' && peek(1) == '-';
    if (is_post_increment || is_post_decrement) {
      if (!expr.as<Variable>() && !expr.as<Map>() && !expr.as<MapAccess>()) {
        auto [op_line, op_col] = get_current_line_col();
        advance(2);
        error("increment/decrement requires a variable or map",
              op_line,
              op_col,
              line_,
              col_);
        break;
      }
      advance(2);
      auto loc = make_loc(expr_begin.line, expr_begin.column, line_, col_);
      auto *unop = ctx_.make_node<Unop>(loc,
                                        std::move(expr),
                                        is_post_increment
                                            ? Operator::POST_INCREMENT
                                            : Operator::POST_DECREMENT);
      expr = Expression(unop);
      continue;
    }

    // No postfix op found
    sp.restore();
    break;
  }

  return expr;
}

// Primary expressions: atoms, calls, parenthesized/tuple/record exprs,
// if-expressions, sizeof, offsetof, typeinfo, comptime.
Expression Parser::parse_primary()
{
  PARSE_TRACE("parse_primary, next='" << peek() << "'");
  consume_layout();
  auto [begin_line, begin_col] = get_current_line_col();

  // Parenthesized expression, cast, tuple, or record.
  if (peek() == '(') {
    return parse_paren_expr();
  }

  // If expression: if cond { expr } else { expr }
  if (match("if")) {
    // When the condition is parenthesized, consume the parens explicitly and
    // parse a full expression inside. This prevents the paren content from
    // being misinterpreted as a record.
    // Without parens, parse as a unary expression so that the opening '{' of
    // the block is not consumed as part of a binary expression.
    Expression cond;
    consume_layout();
    if (peek() == '(') {
      advance(); // consume '('
      cond = parse_expression();
      expect(')');
    } else {
      cond = parse_unary();
    }
    auto *then_block = parse_block();
    consume_layout();
    Expression else_expr;
    if (match("else")) {
      consume_layout();
      if (peek() == '{') {
        auto *else_block = parse_block();
        else_expr = Expression(else_block);
      } else if (check_keyword("if")) {
        // else if ...
        else_expr = parse_primary();
      } else {
        error("expected '{' or 'if' after 'else'");
      }
    } else {
      auto *none = make_none();
      else_expr = Expression(none);
    }
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *if_node = ctx_.make_node<IfExpr>(
        loc, std::move(cond), then_block, std::move(else_expr));
    return { if_node };
  }

  // sizeof(type_or_expr)
  if (match("sizeof")) {
    expect('(');
    consume_layout();

    if (auto type_ref = try_parse_type_reference(")")) {
      expect(')');
      auto loc = make_loc(begin_line, begin_col, line_, col_);
      if (auto *stype = std::get_if<SizedType>(&*type_ref)) {
        auto *s = ctx_.make_node<Sizeof>(loc,
                                         normalize_array_to_sized_type(*stype));
        return { s };
      }
      auto *s = ctx_.make_node<Sizeof>(
          loc, std::move(std::get<Expression>(*type_ref)));
      return { s };
    }
    auto expr = parse_expression();
    expect(')');
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *s = ctx_.make_node<Sizeof>(loc, std::move(expr));
    return { s };
  }

  // offsetof(type, field.field...)
  if (match("offsetof")) {
    expect('(');
    consume_layout();

    // Try type first (struct Name)
    auto sp = save_point();
    auto ident = consume_identifier().value_or("");
    bool is_struct_type = (ident == "struct" || ident == "union" ||
                           ident == "enum");
    sp.restore();

    if (is_struct_type) {
      auto stype = parse_sized_type();
      expect(',');
      auto fields = parse_field_access();
      expect(')');
      auto loc = make_loc(begin_line, begin_col, line_, col_);
      auto *o = ctx_.make_node<Offsetof>(loc,
                                         normalize_array_to_sized_type(stype),
                                         std::move(fields));
      return { o };
    }
    // Expression form: offsetof(expr, field)
    auto expr = parse_expression();
    expect(',');
    auto fields = parse_field_access();
    expect(')');
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *o = ctx_.make_node<Offsetof>(loc, std::move(expr), std::move(fields));
    return { o };
  }

  // typeinfo(type_or_expr)
  if (match("typeinfo")) {
    expect('(');
    auto *typeof_node = parse_type_annotation();
    expect(')');
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *ti = ctx_.make_node<Typeinfo>(loc, typeof_node);
    return { ti };
  }

  // comptime expr
  if (match("comptime")) {
    auto expr = parse_unary();
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *ct = ctx_.make_node<Comptime>(loc, std::move(expr));
    return { ct };
  }

  // Block expression: { stmts; expr }
  if (peek() == '{') {
    auto *block = parse_block();
    if (block) {
      return { block };
    }
    auto *none = make_none();
    return { none };
  }

  // Try to read an identifier - could be a function call, builtin, or keyword.
  auto name = consume_identifier();
  if (name) {
    auto name_loc = make_loc(begin_line, begin_col, line_, col_);

    // Boolean literals.
    if (*name == "true" || *name == "false") {
      auto *boolean = ctx_.make_node<Boolean>(name_loc, *name == "true");
      return { boolean };
    }

    consume_layout();
    if (peek() == '(') {
      return parse_call_expression(*name, name_loc);
    }
    if (is_builtin(*name)) {
      auto *builtin = ctx_.make_node<Builtin>(name_loc, std::move(*name));
      return { builtin };
    }
    // Just an identifier.
    auto *ident = ctx_.make_node<Identifier>(name_loc, std::move(*name));
    return { ident };
  }

  // Try a map (@name or @name[key]).
  if (peek() == '@') {
    return parse_map_with_optional_keys(begin_line, begin_col);
  }

  // Try a variable ($name), positional parameter ($N), or param count ($#).
  if (peek() == '$') {
    if (peek(1) == '#') {
      advance(2);
      auto loc = make_loc(begin_line, begin_col, line_, col_);
      auto *ppc = ctx_.make_node<PositionalParameterCount>(loc);
      return { ppc };
    }

    if (std::isdigit(peek(1))) {
      advance();
      std::string digits;
      while (!at_end() && std::isdigit(peek())) {
        digits += peek();
        advance();
      }
      auto loc = make_loc(begin_line, begin_col, line_, col_);
      try {
        long n = std::stol(digits);
        if (n < 1) {
          error("param $" + digits + " is out of integer range [1, " +
                    std::to_string(std::numeric_limits<long>::max()) + "]",
                begin_line,
                begin_col,
                line_,
                col_);
        }
        auto *pp = ctx_.make_node<PositionalParameter>(loc, n);
        return { pp };
      } catch (...) {
        error("param $" + digits + " is out of integer range [1, " +
                  std::to_string(std::numeric_limits<long>::max()) + "]",
              begin_line,
              begin_col,
              line_,
              col_);
        auto *pp = ctx_.make_node<PositionalParameter>(loc, 0);
        return { pp };
      }
    }

    auto var_name = consume_variable();
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *var = ctx_.make_node<Variable>(loc, var_name);
    return { var };
  }

  // Try an integer literal.
  if (std::isdigit(peek())) {
    auto int_str = consume_integer_str();
    auto res = util::to_uint(int_str, 0);
    if (res) {
      auto loc = make_loc(begin_line, begin_col, line_, col_);
      auto *integer = ctx_.make_node<Integer>(loc, *res, std::move(int_str));
      return { integer };
    }

    std::stringstream ss;
    ss << res.takeError();
    error(ss.str(), begin_line, begin_col, line_, col_);
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *integer = ctx_.make_node<Integer>(loc, 0);
    return { integer };
  }

  // Try a string literal.
  if (peek() == '"') {
    auto str = consume_string();
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *string_node = ctx_.make_node<String>(loc, std::move(str));
    return { string_node };
  }

  error("expected expression");
  auto *none = make_none();
  return { none };
}

// Parse parenthesized expressions, casts, tuples, and records.
Expression Parser::parse_paren_expr()
{
  auto [begin_line, begin_col] = get_current_line_col();

  advance(); // consume '('
  consume_layout();

  // Empty tuple: ()
  if (peek() == ')') {
    advance();
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *tuple = ctx_.make_node<Tuple>(loc, ExpressionList{});
    return { tuple };
  }

  if (auto record = try_parse_record(begin_line, begin_col)) {
    return std::move(*record);
  }

  if (auto cast = try_parse_cast_expr(begin_line, begin_col)) {
    return std::move(*cast);
  }

  return parse_tuple_or_grouping_expr(begin_line, begin_col);
}

std::optional<Expression> Parser::try_parse_record(int begin_line,
                                                   int begin_col)
{
  // (ident=expr, ident_b=expr, ...)
  size_t p = scan_layout(pos_);
  char ch = char_at(p);
  if (!is_identifier_start(ch)) {
    return std::nullopt;
  }

  size_t id_start = p;
  p = scan_identifier_end(p);
  size_t id_end = p;
  p = scan_layout(p);
  if (char_at(p) != '=' || char_at(p + 1) == '=') {
    return std::nullopt;
  }

  if (is_builtin(view(id_start, id_end))) {
    return std::nullopt;
  }

  NamedArgumentList named_args;
  std::set<std::string> seen_names;
  bool record_error = false;
  while (true) {
    consume_layout();
    auto [arg_line, arg_col] = get_current_line_col();
    auto arg_name = consume_identifier("expected identifier");
    if (!arg_name) {
      record_error = true;
      break;
    }
    expect('=');
    auto arg_expr = parse_expression();
    auto arg_loc = make_loc(arg_line, arg_col, line_, col_);
    if (seen_names.contains(*arg_name)) {
      error("Named argument list already contains name: " + *arg_name,
            arg_line,
            arg_col,
            line_,
            col_);
    } else {
      seen_names.insert(*arg_name);
    }
    named_args.push_back(ctx_.make_node<NamedArgument>(arg_loc,
                                                       std::move(*arg_name),
                                                       std::move(arg_expr)));
    if (!match(',')) {
      break;
    }
  }

  if (record_error) {
    // Skip to closing ')' to avoid cascading errors.
    int depth = 1;
    while (!at_end() && depth > 0) {
      char next = peek();
      if (next == '(') {
        depth++;
      } else if (next == ')') {
        depth--;
      }
      if (depth > 0) {
        advance();
      }
    }
  }

  expect(')');
  auto loc = make_loc(begin_line, begin_col, line_, col_);
  auto *record = ctx_.make_node<Record>(loc, std::move(named_args));
  return Expression(record);
}

std::optional<Expression> Parser::try_parse_cast_expr(int begin_line,
                                                      int begin_col)
{
  auto sp = save_point();
  Typeof *typeof_node = nullptr;
  if (check_keyword("typeof")) {
    typeof_node = parse_type_annotation();
  } else {
    consume_layout();
    auto [type_begin_line, type_begin_col] = get_current_line_col();
    if (auto type_ref = try_parse_type_reference(")")) {
      auto loc = make_loc(type_begin_line, type_begin_col, line_, col_);
      if (auto *stype = std::get_if<SizedType>(&*type_ref)) {
        typeof_node = ctx_.make_node<Typeof>(
            loc, normalize_array_to_sized_type(*stype));
      } else {
        typeof_node = ctx_.make_node<Typeof>(
            loc, std::move(std::get<Expression>(*type_ref)));
      }
    } else {
      sp.restore();
      return std::nullopt;
    }
  }

  if (!expect(')') || !can_start_expression()) {
    sp.restore();
    return std::nullopt;
  }

  auto loc = make_loc(begin_line, begin_col, line_, col_);
  auto cast_target = parse_unary();
  auto *cast = ctx_.make_node<Cast>(loc, typeof_node, std::move(cast_target));
  return Expression(cast);
}

Expression Parser::parse_tuple_or_grouping_expr(int begin_line, int begin_col)
{
  auto first = parse_expression();
  consume_layout();

  // Simple parenthesized expression.
  if (peek() != ',') {
    expect(')');
    return first;
  }

  // Tuple: (expr, ...) or (expr,)
  advance();
  consume_layout();

  ExpressionList elems;
  elems.push_back(std::move(first));

  // (expr,) — single-element tuple with trailing comma
  if (peek() == ')') {
    advance();
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *tuple = ctx_.make_node<Tuple>(loc, std::move(elems));
    return { tuple };
  }

  // Multi-element tuple
  elems.push_back(parse_expression());
  while (match(',')) {
    consume_layout();
    if (peek() == ')') {
      break; // trailing comma
    }
    elems.push_back(parse_expression());
  }
  expect(')');
  auto loc = make_loc(begin_line, begin_col, line_, col_);
  auto *tuple = ctx_.make_node<Tuple>(loc, std::move(elems));
  return { tuple };
}

Expression Parser::parse_call_expression(const std::string &name,
                                         const SourceLocation &start_loc)
{
  expect('(');

  ExpressionList args;
  consume_layout();
  if (peek() != ')') {
    args.push_back(parse_expression());
    while (match(',')) {
      args.push_back(parse_expression());
    }
  }

  expect(')');

  auto loc = make_loc(
      start_loc.begin.line, start_loc.begin.column, line_, col_);
  auto *call = ctx_.make_node<Call>(loc, std::string(name), std::move(args));
  return { call };
}

// Expression helpers

Expression Parser::parse_map_with_optional_keys(int begin_line, int begin_col)
{
  auto map_name = consume_map(); // may be empty for anonymous map
  auto map_loc = make_loc(begin_line, begin_col, line_, col_);
  auto *map = ctx_.make_node<Map>(map_loc, map_name);

  consume_layout();
  if (peek() != '[') {
    return { map };
  }

  advance();
  ExpressionList keys;
  keys.push_back(parse_expression());
  while (match(',')) {
    keys.push_back(parse_expression());
  }
  expect(']');
  auto access_loc = make_loc(begin_line, begin_col, line_, col_);
  Expression key_expr;
  if (keys.size() > 1) {
    auto *tuple = ctx_.make_node<Tuple>(access_loc, std::move(keys));
    key_expr = Expression(tuple);
  } else {
    key_expr = std::move(keys.back());
  }
  auto *map_access = ctx_.make_node<MapAccess>(access_loc,
                                               map,
                                               std::move(key_expr));
  return { map_access };
}

std::vector<std::string> Parser::parse_field_access()
{
  std::vector<std::string> fields;

  fields.push_back(consume_identifier().value_or(""));
  while (true) {
    consume_layout();
    if (match('.')) {
      fields.push_back(consume_identifier().value_or(""));
    } else {
      break;
    }
  }
  return fields;
}

// Lexer helpers

void Parser::advance(int n)
{
  for (int i = 0; i < n && !at_end(); i++) {
    if (at(pos_) == '\n') {
      line_++;
      col_ = 1;
    } else {
      col_++;
    }
    pos_++;
  }
}

char Parser::peek(size_t offset) const
{
  if (!in_bounds(pos_ + offset)) {
    return '\0';
  }
  return at(pos_ + offset);
}

char Parser::char_at(size_t pos) const
{
  return in_bounds(pos) ? at(pos) : '\0';
}

bool Parser::at_end() const
{
  return !in_bounds(pos_);
}

char Parser::previous_non_hspace() const
{
  size_t p = pos_;

  while (p > 0) {
    p--;
    char c = at(p);
    if (!is_hspace(c)) {
      return c;
    }
  }
  return '\0';
}

void Parser::consume_line_comment()
{
  advance(2);
  if (!at_end() && peek() == ' ') {
    advance();
  }

  int begin_line = line_;
  int begin_col = col_;
  while (!at_end() && peek() != '\n') {
    advance();
  }

  ctx_.add_comment(make_loc(begin_line, begin_col, line_, col_));
}

void Parser::consume_block_comment()
{
  // Skip the opening "/*"
  advance(2);
  // Skip an optional space after "/*" (e.g. "/* comment" -> "comment")
  if (!at_end() && peek() == ' ') {
    advance();
  }

  while (!at_end()) {
    // Record the content of each line within the block comment
    int begin_line = line_;
    int begin_col = col_;
    while (!at_end()) {
      char next = peek();
      if (next == '\n' || (next == '*' && peek(1) == '/'))
        break;
      advance();
    }

    // Store this line's comment text if it was non-empty
    if (line_ != begin_line || col_ != begin_col) {
      ctx_.add_comment(make_loc(begin_line, begin_col, line_, col_));
    }

    // Check for closing "*/"
    if (!at_end() && peek() == '*' && peek(1) == '/') {
      advance(2);
      break;
    }

    if (at_end()) {
      break;
    }

    // Skip the newline character
    advance();

    // Skip leading horizontal whitespace on the new line
    while (!at_end()) {
      char next = peek();
      if (!is_hspace(next))
        break;
      advance();
    }

    // Re-check for closing "*/" after whitespace (e.g. "  */")
    if (peek() == '*' && peek(1) == '/') {
      continue;
    }

    // Strip leading stars and one optional space that are common in
    // block comment formatting (e.g. " * comment text")
    bool stripped_stars = false;
    while (!at_end() && peek() == '*') {
      stripped_stars = true;
      advance();
    }
    if (stripped_stars && !at_end() && peek() == ' ') {
      advance();
    }

    // If this line is blank or ends immediately with "*/", record an
    // empty comment to preserve blank lines within the block comment
    char next = peek();
    if (next == '\n' || (next == '*' && peek(1) == '/')) {
      ctx_.add_comment(make_loc(line_, col_, line_, col_));
    }
  }
}

void Parser::consume_layout()
{
  bool just_consumed_comment = false;

  while (!at_end()) {
    char next = peek();
    if (is_hspace(next)) {
      advance();
    } else if (next == '\n') {
      int begin_line = line_;
      int begin_col = col_;
      bool suppress_vspace = just_consumed_comment;
      if (!suppress_vspace) {
        char prev = previous_non_hspace();
        suppress_vspace = prev == ';' || prev == '{' || prev == '}';
      }

      advance();
      if (!suppress_vspace) {
        ctx_.add_vspace(make_loc(begin_line, begin_col, line_, col_), 1);
      }
      just_consumed_comment = false;
    } else if (next == '/') {
      char next_next = peek(1);
      if (next_next == '/') {
        consume_line_comment();
        just_consumed_comment = true;
      } else if (next_next == '*') {
        consume_block_comment();
        just_consumed_comment = true;
      } else {
        break;
      }
    } else {
      break;
    }
  }
}

size_t Parser::scan_layout(size_t pos) const
{
  while (in_bounds(pos)) {
    char ch = at(pos);
    if (std::isspace(static_cast<unsigned char>(ch))) {
      pos++;
    } else if (ch == '/') {
      char next = char_at(pos + 1);
      if (next == '/') {
        while (char_at(pos) != '\n' && in_bounds(pos)) {
          pos++;
        }
      } else if (next == '*') {
        pos += 2;
        while (in_bounds(pos)) {
          if (at(pos) == '*' && char_at(pos + 1) == '/') {
            pos += 2;
            break;
          }
          pos++;
        }
      } else {
        break;
      }
    } else {
      break;
    }
  }
  return pos;
}

bool Parser::is_hspace(char c)
{
  return c == ' ' || c == '\t' || c == '\r';
}

bool Parser::is_identifier_start(char c)
{
  return std::isalpha(static_cast<unsigned char>(c)) || c == '_';
}

bool Parser::is_identifier_body(char c)
{
  return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
}

size_t Parser::scan_identifier_end(size_t pos) const
{
  char ch;
  while ((ch = char_at(pos)) != '\0' && is_identifier_body(ch)) {
    pos++;
  }
  return pos;
}

size_t Parser::scan_balanced(size_t pos, char open, char close) const
{
  if (char_at(pos) != open) {
    return pos;
  }

  int depth = 1;
  pos++;
  while (in_bounds(pos) && depth > 0) {
    if (at(pos) == open) {
      depth++;
    } else if (at(pos) == close) {
      depth--;
    }
    pos++;
  }
  return pos;
}

size_t Parser::scan_pointer_suffix(size_t pos) const
{
  pos = scan_layout(pos);
  while (char_at(pos) == '*') {
    pos++;
    pos = scan_layout(pos);
  }
  return pos;
}

std::string_view Parser::view(size_t start, size_t end) const
{
  return std::string_view(*input_).substr(start, end - start);
}

std::string_view Parser::peek_keyword() const
{
  return view(pos_, scan_identifier_end(pos_));
}

bool Parser::match(char c)
{
  consume_layout();
  if (peek() == c) {
    advance();
    return true;
  }
  return false;
}

bool Parser::match(const std::string &s)
{
  consume_layout();
  if (!in_bounds(pos_ + s.size() - 1)) {
    return false;
  }
  for (size_t i = 0; i < s.size(); i++) {
    if (at(pos_ + i) != s[i]) {
      return false;
    }
  }
  // Make sure the keyword isn't a prefix of a longer identifier.
  char after = char_at(pos_ + s.size());
  if (is_identifier_body(after)) {
    return false;
  }
  for (size_t i = 0; i < s.size(); i++) {
    advance();
  }
  return true;
}

bool Parser::check_keyword(const std::string &s) const
{
  size_t p = scan_layout(pos_);

  if (!in_bounds(p + s.size() - 1)) {
    return false;
  }
  for (size_t i = 0; i < s.size(); i++) {
    if (at(p + i) != s[i]) {
      return false;
    }
  }
  // Ensure it's not a prefix of a longer identifier.
  char after = char_at(p + s.size());
  return !is_identifier_body(after);
}

bool Parser::expect(char c)
{
  if (!match(c)) {
    error(std::string("expected '") + c + "'");
    return false;
  }
  return true;
}

bool Parser::expect(const std::string &s)
{
  if (!match(s)) {
    error("expected '" + s + "'");
    return false;
  }
  return true;
}

std::string Parser::consume_ident_from(size_t scan_start)
{
  size_t start = pos_;
  size_t end = scan_identifier_end(scan_start);
  pos_ = end;
  col_ += static_cast<int>(end - start);
  return std::string(view(start, end));
}

std::optional<std::string> Parser::consume_identifier(std::string err_msg)
{
  consume_layout();
  if (!is_identifier_start(peek())) {
    if (!err_msg.empty()) {
      error(err_msg);
    }
    return std::nullopt;
  }
  return consume_ident_from(pos_);
}

std::string Parser::consume_variable()
{
  if (!is_identifier_start(peek(1))) {
    error("expected identifier after '$'");
    return "";
  }
  return consume_ident_from(pos_ + 1);
}

std::string Parser::consume_map()
{
  // Unlike variables, maps can be a bare sigil
  if (!is_identifier_start(peek(1))) {
    advance();
    return "@";
  }
  return consume_ident_from(pos_ + 1);
}

std::string Parser::consume_string()
{
  // Opening quote already confirmed by caller, consume it.
  advance();
  std::string result;
  while (!at_end()) {
    char next = peek();
    if (next == '"')
      break;
    if (next == '\n') {
      error("unterminated string");
      return result;
    }
    if (next != '\\') {
      result += next;
      advance();
      continue;
    }
    int esc_line = line_;
    int esc_col = col_;
    advance();
    if (at_end()) {
      error("unterminated string");
      return result;
    }
    char esc = peek();
    switch (esc) {
      case 'n':
        result += '\n';
        break;
      case 't':
        result += '\t';
        break;
      case 'r':
        result += '\r';
        break;
      case '"':
        result += '"';
        break;
      case '\\':
        result += '\\';
        break;
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7': {
        // Octal escape: up to 3 octal digits.
        std::string oct;
        oct += esc;
        advance();
        for (int i = 0; i < 2 && !at_end(); i++) {
          char next = peek();
          if (next < '0' || next > '7')
            break;
          oct += next;
          advance();
        }
        long value = std::strtol(oct.c_str(), nullptr, 8);
        if (value > UCHAR_MAX) {
          error("octal escape sequence out of range '\\" + oct + "'",
                esc_line,
                esc_col,
                line_,
                col_);
        }
        result += static_cast<char>(value);
        continue; // Already advanced past octal digits.
      }
      case 'x':
      case 'X': {
        advance();
        std::string hex;
        for (int i = 0; i < 2 && !at_end(); i++) {
          char next = peek();
          if (!std::isxdigit(next))
            break;
          hex += next;
          advance();
        }
        if (hex.empty()) {
          error("invalid hex escape sequence");
        } else {
          result += static_cast<char>(std::strtol(hex.c_str(), nullptr, 16));
        }
        continue; // Already advanced past hex digits.
      }
      default:
        error(std::string("invalid escape character '\\") + esc + "'");
        break;
    }
    advance();
  }
  if (!at_end()) {
    advance(); // Closing quote.
  } else {
    error("unterminated string");
  }
  return result;
}

// Consume an integer literal as a raw string. Handles decimal, hex (0x...),
// exponent notation (NeM), underscore separators, and optional suffixes.
std::string Parser::consume_integer_str()
{
  consume_layout();
  std::string result;

  // Hex prefix
  char next = peek();
  if (next == '0' && (peek(1) == 'x' || peek(1) == 'X')) {
    result += next;
    advance();
    result += peek();
    advance();
    while (!at_end()) {
      char next = peek();
      if (!std::isxdigit(next) && next != '_')
        break;
      result += next;
      advance();
    }
    if (!result.empty() && result.back() == '_') {
      error("trailing underscore in integer literal",
            line_,
            col_ - 1,
            line_,
            col_);
    }
    return result;
  }

  // Decimal digits with possible underscores
  while (!at_end()) {
    char next = peek();
    if (!std::isdigit(next) && next != '_')
      break;
    result += next;
    advance();
  }

  if (!result.empty() && result.back() == '_') {
    error(
        "trailing underscore in integer literal", line_, col_ - 1, line_, col_);
  }

  // Exponent notation: e.g. 1e6
  if (!at_end()) {
    char ec = peek();
    if (ec == 'e' || ec == 'E') {
      result += ec;
      advance();
      while (!at_end()) {
        char next = peek();
        if (!std::isdigit(next) && next != '_')
          break;
        result += next;
        advance();
      }
      if (!result.empty() && result.back() == '_') {
        error("trailing underscore in integer literal",
              line_,
              col_ - 1,
              line_,
              col_);
      }
    }
  }

  // Optional suffix (u, l, ll, ul, ull, ns, us, ms, s, m, h, d)
  if (!at_end()) {
    char sc = peek();
    // Check for time/size suffixes: ns, us, ms
    if ((sc == 'n' || sc == 'u' || sc == 'm') && peek(1) == 's') {
      result += sc;
      advance();
      result += peek();
      advance();
    } else if (sc == 's' || sc == 'm' || sc == 'h' || sc == 'd') {
      result += sc;
      advance();
    } else if (sc == 'u' || sc == 'U') {
      result += sc;
      advance();
      // Possible 'l' or 'll' after 'u'
      if (!at_end()) {
        char lc = peek();
        if (lc == 'l' || lc == 'L') {
          result += lc;
          advance();
          if (!at_end()) {
            lc = peek();
            if (lc == 'l' || lc == 'L') {
              result += lc;
              advance();
            }
          }
        }
      }
    } else if (sc == 'l' || sc == 'L') {
      result += sc;
      advance();
      if (!at_end()) {
        char lc = peek();
        if (lc == 'l' || lc == 'L') {
          result += lc;
          advance();
        }
      }
    }
  }

  // If alphanumeric characters still follow, the suffix is invalid.
  // Consume them to avoid cascading errors.
  if (!at_end()) {
    char fc = peek();
    if (is_identifier_start(fc)) {
      auto [err_line, err_col] = get_current_line_col();
      std::string bad;
      while (!at_end()) {
        char next = peek();
        if (!is_identifier_body(next))
          break;
        bad += next;
        advance();
      }
      error("invalid integer suffix '" + bad + "'",
            err_line,
            err_col,
            line_,
            col_);
    }
  }

  return result;
}

// Error reporting

bool Parser::has_errors() const
{
  return ctx_.state_->diagnostics_->error_count() > 0;
}

void Parser::error(const std::string &msg)
{
  auto sp = save_point();
  consume_layout();
  auto [begin_line, begin_col] = get_current_line_col();

  // Scan past the current token to find its end.
  if (!at_end()) {
    char next = peek();
    if (is_identifier_start(next)) {
      while (!at_end()) {
        char next = peek();
        if (!is_identifier_body(next))
          break;
        advance();
      }
    } else if (std::isdigit(next)) {
      while (!at_end()) {
        char next = peek();
        if (!std::isalnum(next) && next != '.')
          break;
        advance();
      }
    } else if (next == '@' || next == '$') {
      advance();
      while (!at_end()) {
        char next = peek();
        if (!is_identifier_body(next))
          break;
        advance();
      }
    } else {
      advance();
    }
  }

  auto [end_line, end_col] = get_current_line_col();
  sp.restore();

  error(msg, begin_line, begin_col, end_line, end_col);
}

void Parser::error(const std::string &msg,
                   int begin_line,
                   int begin_col,
                   int end_line,
                   int end_col)
{
  auto loc = make_loc(begin_line, begin_col, end_line, end_col);
  SourceLocation valid(ctx_.source());
  valid.begin = loc.begin;
  valid.end = loc.end;
  ctx_.state_->diagnostics_->addError(
      std::make_shared<LocationChain>(std::move(valid)))
      << "syntax: " << msg;
}

// Source location tracking

SourceLocation Parser::make_loc(int begin_line,
                                int begin_col,
                                int end_line,
                                int end_col) const
{
  SourceLocation loc(ctx_.source());
  loc.begin.line = begin_line;
  loc.begin.column = begin_col;
  loc.end.line = end_line;
  loc.end.column = end_col;
  return loc;
}

None *Parser::make_none()
{
  return ctx_.make_node<None>(make_loc(line_, col_, line_, col_));
}

Parser::LineCol Parser::get_current_line_col()
{
  return { .line = line_, .col = col_ };
}

// Lookahead helpers

bool Parser::is_builtin(std::string_view name)
{
  static const std::unordered_set<std::string_view> builtins = {
    "args",
    "ctx",
    "kstack",
    "nsecs",
    "pid",
    "tid",
    "ustack",
    "__builtin_cgroup",
    "__builtin_comm",
    "__builtin_cpid",
    "__builtin_cpu",
    "__builtin_curtask",
    "__builtin_elapsed",
    "__builtin_func",
    "__builtin_gid",
    "__builtin_jiffies",
    "__builtin_ncpus",
    "__builtin_probe",
    "__builtin_rand",
    "__builtin_retval",
    "__builtin_uid",
    "__builtin_usermode",
    "__builtin_username",
  };
  if (builtins.contains(name)) {
    return true;
  }

  // Handle parameterized builtins: arg0-arg9+, sarg0-sarg9
  if (name.size() >= 4 && name.starts_with("arg") &&
      std::all_of(name.begin() + 3, name.end(), [](char c) {
        return std::isdigit(static_cast<unsigned char>(c));
      })) {
    return true;
  }
  if (name.size() >= 5 && name.starts_with("sarg") &&
      std::all_of(name.begin() + 4, name.end(), [](char c) {
        return std::isdigit(static_cast<unsigned char>(c));
      })) {
    return true;
  }

  return false;
}

bool Parser::can_start_expression() const
{
  size_t p = scan_layout(pos_);
  char c = char_at(p);
  return std::isdigit(static_cast<unsigned char>(c)) || c == '$' || c == '@' ||
         c == '"' || c == '(' || c == '-' || c == '!' || c == '~' || c == '*' ||
         c == '&' || is_identifier_start(c);
}

bool Parser::looks_like_c_definition() const
{
  size_t p = scan_layout(pos_);
  // Skip keyword (struct/union/enum), then accept an arbitrary sequence of
  // identifiers and balanced (...) / [...] groups before the opening brace.
  // This covers declarations like:
  //   struct Foo __attribute__((packed)) {
  // while still rejecting attach points such as:
  //   struct:probe { ... }
  p = scan_identifier_end(p);
  p = scan_layout(p);

  while (in_bounds(p)) {
    char ch = char_at(p);
    if (ch == '{') {
      return true;
    }
    if (ch == ':' || ch == '/' || ch == ',' || ch == ';') {
      return false;
    }
    if (is_identifier_start(ch)) {
      p = scan_identifier_end(p);
      p = scan_layout(p);
      continue;
    }
    if (ch == '(' || ch == '[') {
      char close = ch == '(' ? ')' : ']';
      size_t after = scan_balanced(p, ch, close);
      if (after == p || char_at(after - 1) != close) {
        return false;
      }
      p = scan_layout(after);
      continue;
    }
    return false;
  }

  return false;
}

Pass CreateParsePass(bool debug)
{
  return Pass::create("parse", [=](ASTContext &ast) {
    Parser parser(ast, debug);
    ast.root = parser.parse();
  });
}

} // namespace bpftrace
