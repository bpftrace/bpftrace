#include "rd_parser.h"

#include <functional>
#include <set>
#include <sstream>
#include <unordered_set>

#include "log.h"
#include "util/int_parser.h"

namespace bpftrace {

// Public Methods

ast::Program *RDParser::parse()
{
  input_ = &ctx_.source_->contents;
  pos_ = 0;
  line_ = 1;
  col_ = 1;
  return parse_program();
}

// For the CMacroExpander pass
std::optional<ast::Expression> RDParser::parse_expr()
{
  input_ = &ctx_.source_->contents;
  pos_ = 0;
  line_ = 1;
  col_ = 1;
  skip_whitespace();
  if (at_end()) {
    return std::nullopt;
  }
  auto expr = parse_expression();
  if (ctx_.diagnostics().ok()) {
    return expr;
  }
  return std::nullopt;
}

// Grammar rules

ast::Program *RDParser::parse_program()
{
  ast::RootImportList imports;
  ast::RootStatements root_stmts;

  // Preamble: config and imports must appear before everything else.
  // They can be in any order relative to each other.
  ast::CStatementList c_stmts;
  ast::Config *config = nullptr;
  skip_whitespace();
  while (!at_end()) {
    // Config block (at most one).
    if (check_keyword("config")) {
      if (!config) {
        config = parse_config();
      } else {
        auto saved_pos = get_current_line_col();
        match("config");
        error("duplicate config block",
              saved_pos.line,
              saved_pos.col,
              line_,
              col_);
        // Skip past the config block to avoid cascading errors.
        skip_whitespace();
        if (match('=')) {
          skip_whitespace();
          if (match('{')) {
            int depth = 1;
            while (!at_end() && depth > 0) {
              if (peek() == '{')
                depth++;
              else if (peek() == '}')
                depth--;
              if (depth > 0)
                advance();
            }
            if (!at_end())
              advance(); // skip closing '}'
          }
        }
      }
      skip_whitespace();
      continue;
    }
    // Root-level imports.
    if (check_keyword("import")) {
      auto *imp = parse_root_import();
      if (imp)
        imports.push_back(imp);
      skip_whitespace();
      continue;
    }
    break;
  }

  // C definitions: #include, struct/union/enum definitions.
  // Must appear after config/imports but before probes/macros/functions.
  skip_whitespace();
  while (!at_end()) {
    // C preprocessor directives: #include, #define, etc.
    if (peek() == '#' &&
        (pos_ + 1 >= input_->size() || (*input_)[pos_ + 1] != '!')) {
      c_stmts.push_back(parse_c_preprocessor());
      skip_whitespace();
      continue;
    }
    // C struct/union/enum definitions: struct Name { ... }
    if ((check_keyword("struct") || check_keyword("union") ||
         check_keyword("enum")) &&
        looks_like_c_definition()) {
      c_stmts.push_back(parse_c_definition());
      skip_whitespace();
      continue;
    }
    break;
  }

  // Main loop: probes, macros, functions, and map declarations.
  while (!at_end()) {
    skip_whitespace();
    if (at_end())
      break;
    size_t before = pos_;
    // C preprocessor directives (#include, #define, etc.)
    if (peek() == '#' &&
        (pos_ + 1 >= input_->size() || (*input_)[pos_ + 1] != '!')) {
      auto saved_pos = get_current_line_col();
      c_stmts.push_back(parse_c_preprocessor());
      error("C definitions must appear before probes and functions",
            saved_pos.line,
            saved_pos.col,
            line_,
            col_);
    }
    // C struct/union/enum definitions at root level
    else if ((check_keyword("struct") || check_keyword("union") ||
              check_keyword("enum"))) {
      if (looks_like_c_definition()) {
        auto saved_pos = get_current_line_col();
        c_stmts.push_back(parse_c_definition());
        error("C definitions must appear before probes and functions",
              saved_pos.line,
              saved_pos.col,
              line_,
              col_);
      } else {
        // Not a C definition — treat as probe.
        auto *probe = parse_probe();
        if (probe)
          root_stmts.emplace_back(probe);
      }
    } else if (check_keyword("config")) {
      auto saved_pos = get_current_line_col();
      match("config");
      error("config must appear before probes and functions",
            saved_pos.line,
            saved_pos.col,
            line_,
            col_);
      // Skip past the config block to avoid cascading errors.
      skip_whitespace();
      if (match('=')) {
        skip_whitespace();
        if (match('{')) {
          int depth = 1;
          while (!at_end() && depth > 0) {
            if (peek() == '{')
              depth++;
            else if (peek() == '}')
              depth--;
            if (depth > 0)
              advance();
          }
          if (!at_end())
            advance(); // skip closing '}'
        }
      }
    } else if (check_keyword("import")) {
      auto saved_pos = get_current_line_col();
      match("import");
      error("imports must appear before probes and functions",
            saved_pos.line,
            saved_pos.col,
            line_,
            col_);
      // Skip past the import statement.
      while (!at_end() && peek() != ';' && peek() != '\n')
        advance();
      match(';');
    } else if (check_keyword("macro")) {
      auto *macro = parse_macro();
      if (macro)
        root_stmts.emplace_back(macro);
    } else if (check_keyword("fn")) {
      auto *subprog = parse_subprog();
      if (subprog)
        root_stmts.emplace_back(subprog);
    } else if (check_keyword("let")) {
      // At root level, `let @...` is a map declaration.
      size_t p = pos_;
      while (p < input_->size() && std::isspace((*input_)[p]))
        p++;
      p += 3; // skip "let"
      while (p < input_->size() && std::isspace((*input_)[p]))
        p++;
      if (p < input_->size() && (*input_)[p] == '@') {
        auto *map_decl = parse_map_decl_stmt();
        if (map_decl)
          root_stmts.emplace_back(map_decl);
      } else {
        error("root-level let statements need to be map declarations, e.g. let "
              "@a = hash(2);");
        advance();
      }
    } else {
      auto *probe = parse_probe();
      if (probe)
        root_stmts.emplace_back(probe);
    }
    // If nothing was consumed, skip the current character to avoid
    // an infinite loop (e.g. when parsing stdlib files that contain
    // only macros and the last token wasn't recognized).
    if (pos_ == before) {
      error("unexpected input");
      advance();
    }
    skip_whitespace();
  }

  auto loc = make_loc(1, 1, line_, col_);
  if (!config) {
    auto config_loc = make_loc(1, 1, 1, 1);
    config = ctx_.make_node<ast::Config>(config_loc,
                                         ast::ConfigStatementList{});
  }
  return ctx_.make_node<ast::Program>(loc,
                                      std::move(c_stmts),
                                      config,
                                      std::move(imports),
                                      std::move(root_stmts));
}

ast::CStatement *RDParser::parse_c_preprocessor()
{
  int sl = line_, sc = col_;
  std::string line;
  while (!at_end() && peek() != '\n') {
    line += peek();
    advance();
  }
  // Trim trailing whitespace.
  while (!line.empty() && std::isspace(line.back()))
    line.pop_back();
  auto loc = make_loc(sl, sc, line_, col_);
  return ctx_.make_node<ast::CStatement>(loc, std::move(line));
}

ast::CStatement *RDParser::parse_c_definition()
{
  int sl = line_, sc = col_;
  std::string def;
  // Consume keyword and name up to '{'.
  while (!at_end() && peek() != '{') {
    def += peek();
    advance();
  }
  // Consume balanced braces.
  int depth = 0;
  while (!at_end()) {
    if (peek() == '{')
      depth++;
    else if (peek() == '}')
      depth--;
    def += peek();
    advance();
    if (depth == 0)
      break;
  }
  // Trim trailing whitespace.
  while (!def.empty() && std::isspace(def.back()))
    def.pop_back();
  // Ensure trailing semicolon.
  if (!def.empty() && def.back() != ';')
    def += ";";
  // Consume optional trailing semicolon from source.
  skip_whitespace();
  if (!at_end() && peek() == ';')
    advance();
  auto loc = make_loc(sl, sc, line_, col_);
  return ctx_.make_node<ast::CStatement>(loc, std::move(def));
}

ast::Config *RDParser::parse_config()
{
  int start_line = line_;
  int start_col = col_;
  if (!match("config"))
    return nullptr;

  if (!expect('='))
    return nullptr;
  if (!expect('{'))
    return nullptr;

  ast::ConfigStatementList stmts;
  skip_whitespace();
  while (peek() != '}' && !at_end()) {
    int stmt_line = line_;
    int stmt_col = col_;
    auto key = consume_identifier();
    if (key.empty()) {
      error("expected config key");
      break;
    }
    if (!expect('='))
      break;

    skip_whitespace();
    auto stmt_loc = make_loc(stmt_line, stmt_col, line_, col_);

    if (peek() == '"') {
      auto val = consume_string();
      stmt_loc = make_loc(stmt_line, stmt_col, line_, col_);
      stmts.push_back(ctx_.make_node<ast::AssignConfigVarStatement>(
          stmt_loc, std::move(key), std::move(val)));
    } else if (check_keyword("true") || check_keyword("false")) {
      bool val = check_keyword("true");
      if (val)
        match("true");
      else
        match("false");
      stmt_loc = make_loc(stmt_line, stmt_col, line_, col_);
      stmts.push_back(ctx_.make_node<ast::AssignConfigVarStatement>(
          stmt_loc, std::move(key), val));
    } else if (std::isdigit(peek())) {
      auto int_str = consume_integer_str();
      auto res = util::to_uint(int_str, 0);
      if (!res) {
        error("invalid integer in config");
        break;
      }
      stmt_loc = make_loc(stmt_line, stmt_col, line_, col_);
      stmts.push_back(ctx_.make_node<ast::AssignConfigVarStatement>(
          stmt_loc, std::move(key), static_cast<uint64_t>(*res)));
    } else {
      auto val = consume_identifier();
      stmt_loc = make_loc(stmt_line, stmt_col, line_, col_);
      stmts.push_back(ctx_.make_node<ast::AssignConfigVarStatement>(
          stmt_loc, std::move(key), std::move(val)));
    }
    match(';');
    skip_whitespace();
  }

  expect('}');
  auto loc = make_loc(start_line, start_col, line_, col_);
  return ctx_.make_node<ast::Config>(loc, std::move(stmts));
}

ast::RootImport *RDParser::parse_root_import()
{
  int start_line = line_;
  int start_col = col_;
  if (!match("import")) {
    error("expected 'import'");
    return nullptr;
  }

  skip_whitespace();
  if (peek() != '"') {
    error("expected string after 'import'");
    return nullptr;
  }
  auto path = consume_string();
  auto loc = make_loc(start_line, start_col, line_, col_);
  match(';');

  return ctx_.make_node<ast::RootImport>(loc, std::move(path));
}

ast::Macro *RDParser::parse_macro()
{
  int start_line = line_;
  int start_col = col_;
  if (!match("macro")) {
    error("expected 'macro'");
    return nullptr;
  }

  auto name = consume_identifier();
  if (name.empty()) {
    error("expected macro name");
    return nullptr;
  }
  auto name_loc = make_loc(start_line, start_col, line_, col_);

  if (!expect('('))
    return nullptr;

  // Parse macro arguments: $var, @map, or plain identifiers.
  ast::ExpressionList args;
  skip_whitespace();
  if (peek() != ')') {
    args.push_back(parse_macro_arg());
    while (match(',')) {
      args.push_back(parse_macro_arg());
    }
  }

  if (!expect(')'))
    return nullptr;

  auto *block = parse_block();
  if (!block)
    return nullptr;

  return ctx_.make_node<ast::Macro>(
      name_loc, std::move(name), std::move(args), block);
}

ast::Expression RDParser::parse_macro_arg()
{
  skip_whitespace();
  int start_line = line_;
  int start_col = col_;

  if (peek() == '$') {
    advance();
    auto var_name = consume_identifier();
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto *var = ctx_.make_node<ast::Variable>(loc, "$" + var_name);
    return { var };
  }

  if (peek() == '@') {
    advance();
    auto map_name = consume_identifier();
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto *map = ctx_.make_node<ast::Map>(loc, "@" + map_name);
    return { map };
  }

  auto ident = consume_identifier();
  if (!ident.empty()) {
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto *id = ctx_.make_node<ast::Identifier>(loc, std::move(ident));
    return { id };
  }

  error("expected macro argument ($var, @map, or identifier)");
  auto loc = make_loc(start_line, start_col, line_, col_);
  auto *none = ctx_.make_node<ast::None>(loc);
  return { none };
}

ast::Subprog *RDParser::parse_subprog()
{
  int start_line = line_;
  int start_col = col_;
  if (!match("fn")) {
    error("expected 'fn'");
    return nullptr;
  }

  auto name = consume_identifier();
  if (name.empty()) {
    error("expected function name");
    return nullptr;
  }
  auto name_loc = make_loc(start_line, start_col, line_, col_);

  if (!expect('('))
    return nullptr;

  ast::SubprogArgList args;
  skip_whitespace();
  if (peek() != ')') {
    // Parse first arg: $var : type
    do {
      skip_whitespace();
      int arg_line = line_;
      int arg_col = col_;
      if (peek() != '$') {
        error("expected variable in function argument");
        break;
      }
      advance();
      auto var_name = consume_identifier();
      auto var_loc = make_loc(arg_line, arg_col, line_, col_);
      auto *var = ctx_.make_node<ast::Variable>(var_loc, "$" + var_name);
      if (!expect(':'))
        break;
      auto *type = parse_type_annotation();
      if (!type)
        break;
      auto arg_loc = make_loc(arg_line, arg_col, line_, col_);
      args.push_back(ctx_.make_node<ast::SubprogArg>(arg_loc, var, type));
    } while (match(','));
  }

  if (!expect(')'))
    return nullptr;
  if (!expect(':'))
    return nullptr;

  auto *return_type = parse_type_annotation();
  if (!return_type)
    return nullptr;

  auto *block = parse_block(false);
  if (!block)
    return nullptr;

  return ctx_.make_node<ast::Subprog>(
      name_loc, std::move(name), return_type, std::move(args), block);
}

ast::MapDeclStatement *RDParser::parse_map_decl_stmt()
{
  int start_line = line_;
  int start_col = col_;
  if (!match("let")) {
    error("expected 'let'");
    return nullptr;
  }

  skip_whitespace();
  if (peek() != '@') {
    error("expected '@' in map declaration");
    return nullptr;
  }
  advance();
  auto map_name = consume_identifier();
  std::string full_name = "@" + map_name;
  if (map_name.empty())
    full_name = "@";

  if (!expect('='))
    return nullptr;

  auto type_name = consume_identifier();
  if (type_name.empty()) {
    error("expected map type name");
    return nullptr;
  }

  if (!expect('('))
    return nullptr;
  auto int_str = consume_integer_str();
  auto res = util::to_uint(int_str, 0);
  if (!res) {
    error("invalid integer in map declaration");
    return nullptr;
  }
  if (!expect(')'))
    return nullptr;
  match(';');
  auto loc = make_loc(start_line, start_col, line_, col_);

  return ctx_.make_node<ast::MapDeclStatement>(
      loc, std::move(full_name), std::move(type_name), *res);
}

ast::Probe *RDParser::parse_probe()
{
  auto saved_line_col = get_current_line_col();
  ast::AttachPointList attach_points;

  auto *ap = parse_attach_point();
  if (!ap)
    return nullptr;
  attach_points.push_back(ap);

  // Multiple attach points separated by commas.
  while (match(',')) {
    skip_whitespace();
    // Allow trailing comma.
    if (peek() == '/' || peek() == '{')
      break;
    ap = parse_attach_point();
    if (!ap)
      break;
    attach_points.push_back(ap);
  }

  // The probe's location spans only the attach points (not the block).
  // Use the last attach point's end location.
  const auto &last_ap_loc = attach_points.back()->loc->current;
  auto ap_loc = make_loc(saved_line_col.line,
                         saved_line_col.col,
                         last_ap_loc.end.line,
                         last_ap_loc.end.column);

  // Parse optional predicate: /expr/
  int pred_start_line = line_, pred_start_col = col_;
  auto pred = parse_predicate();
  int pred_end_line = line_, pred_end_col = col_;

  auto *block = parse_block(false);
  if (!block)
    return nullptr;

  if (pred.has_value()) {
    // Desugar predicate into: { if pred { <original block> } }
    auto pred_loc = make_loc(
        pred_start_line, pred_start_col, pred_end_line, pred_end_col);
    auto *none = ctx_.make_node<ast::None>(pred_loc);
    auto *cond = ctx_.make_node<ast::IfExpr>(
        pred_loc, pred.value(), block, none);
    block = ctx_.make_node<ast::BlockExpr>(pred_loc,
                                           ast::StatementList{},
                                           cond);
  }

  return ctx_.make_node<ast::Probe>(ap_loc, std::move(attach_points), block);
}

ast::AttachPoint *RDParser::parse_attach_point()
{
  skip_whitespace();
  int start_line = line_;
  int start_col = col_;

  // Consume the raw attach point text. This is everything up to a
  // delimiter that ends the attach point: '{', '/', ',' or unescaped
  // whitespace that is followed by one of those delimiters (or another
  // attach point on a new line).
  //
  // The raw_input is later parsed by the AttachPointParser pass to
  // populate structured fields (provider, target, func, etc.).
  std::string raw;
  while (!at_end()) {
    char c = peek();

    // These always end the attach point.
    if (c == '{' || c == ',')
      break;

    // '/' could be a predicate start or part of a path. It's a path
    // component if we've seen a ':' in the raw text (paths appear after
    // the provider separator, e.g. uprobe:/my/program:func).
    if (c == '/' && !raw.empty() && raw.find(':') == std::string::npos) {
      // No ':' seen yet — this '/' can't be a path, it's a predicate.
      // But check it's not a comment.
      if (pos_ + 1 < input_->size()) {
        char next = (*input_)[pos_ + 1];
        if (next != '/' && next != '*')
          break;
      } else {
        break;
      }
    }

    // Whitespace: stop if what follows (after whitespace) is a delimiter.
    if (std::isspace(c)) {
      size_t p = pos_;
      while (p < input_->size() && std::isspace((*input_)[p]))
        p++;
      if (p >= input_->size())
        break;
      char after = (*input_)[p];
      if (after == '{' || after == ',' || after == '/')
        break;
      // If we hit a newline and the next non-ws char doesn't continue
      // the attach point, stop. Otherwise consume the whitespace.
      break;
    }

    // Quoted string: consume entirely (for things like
    // uprobe:"lib":func).
    if (c == '"') {
      raw += c;
      advance();
      while (!at_end() && peek() != '"') {
        if (peek() == '\\') {
          raw += peek();
          advance();
          if (!at_end()) {
            raw += peek();
            advance();
          }
          continue;
        }
        raw += peek();
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

  auto loc = make_loc(start_line, start_col, line_, col_);
  return ctx_.make_node<ast::AttachPoint>(loc, std::move(raw), false);
}

std::optional<ast::Expression> RDParser::parse_predicate()
{
  skip_whitespace();
  if (peek() != '/')
    return std::nullopt;

  // Make sure this is a predicate '/' and not a comment '//' or '/*'.
  if (pos_ + 1 < input_->size()) {
    char next = (*input_)[pos_ + 1];
    if (next == '/' || next == '*')
      return std::nullopt;
  }

  advance(); // consume opening '/'
  auto expr = parse_expression();

  if (!expect('/')) {
    error("expected '/' to close predicate");
  }

  return expr;
}

ast::BlockExpr *RDParser::parse_block(bool allow_trailing_expr)
{
  auto saved_line_col = get_current_line_col();
  if (!expect('{'))
    return nullptr;

  ast::StatementList stmts;
  std::optional<ast::Expression> trailing_expr;
  skip_whitespace();

  // Recursively normalize block expressions used as statements:
  // convert trailing expressions to statements + None.
  std::function<void(ast::Expression &)> normalize_block;
  normalize_block = [&](ast::Expression &e) {
    auto *block = e.as<ast::BlockExpr>();
    if (block) {
      // First, recursively normalize any block expressions in statements.
      for (auto &s : block->stmts) {
        auto *es = s.as<ast::ExprStatement>();
        if (es) {
          normalize_block(es->expr);
        }
      }
      // Normalize the trailing expression itself.
      auto *inner = block->expr.as<ast::None>();
      if (!inner) {
        normalize_block(block->expr);
        auto *es = ctx_.make_node<ast::ExprStatement>(block->loc,
                                                      std::move(block->expr));
        block->stmts.emplace_back(es);
        auto *none = ctx_.make_node<ast::None>(block->loc);
        block->expr = ast::Expression(none);
      }
    }
    // Normalize if-expression branches.
    auto *if_expr = e.as<ast::IfExpr>();
    if (if_expr) {
      normalize_block(if_expr->left);
      normalize_block(if_expr->right);
    }
  };

  while (peek() != '}' && !at_end()) {
    size_t before = pos_;
    // Statement-level import: import "path";
    if (check_keyword("import")) {
      auto *imp = parse_statement_import();
      if (imp)
        stmts.emplace_back(imp);
      skip_whitespace();
      if (pos_ == before) {
        error("unexpected input in block");
        advance();
      }
      continue;
    }
    // While/unroll statements.
    if (check_keyword("while") || check_keyword("unroll")) {
      auto stmt = parse_while_or_unroll();
      stmts.push_back(std::move(stmt));
      skip_whitespace();
      continue;
    }
    // For statements.
    if (check_keyword("for")) {
      auto stmt = parse_for();
      stmts.push_back(std::move(stmt));
      skip_whitespace();
      continue;
    }
    // Jump statements: break, continue, return.
    if (check_keyword("break")) {
      int sl = line_, sc = col_;
      match("break");
      auto loc = make_loc(sl, sc, line_, col_);
      match(';');
      auto *jump = ctx_.make_node<ast::Jump>(loc, ast::JumpType::BREAK);
      stmts.emplace_back(jump);
      skip_whitespace();
      continue;
    }
    if (check_keyword("continue")) {
      int sl = line_, sc = col_;
      match("continue");
      auto loc = make_loc(sl, sc, line_, col_);
      match(';');
      auto *jump = ctx_.make_node<ast::Jump>(loc, ast::JumpType::CONTINUE);
      stmts.emplace_back(jump);
      skip_whitespace();
      continue;
    }
    if (check_keyword("return")) {
      int sl = line_, sc = col_;
      match("return");
      skip_whitespace();
      if (peek() == ';' || peek() == '}') {
        auto loc = make_loc(sl, sc, line_, col_);
        match(';');
        auto *jump = ctx_.make_node<ast::Jump>(loc, ast::JumpType::RETURN);
        stmts.emplace_back(jump);
      } else {
        auto expr = parse_expression();
        auto loc = make_loc(sl, sc, line_, col_);
        match(';');
        auto *jump = ctx_.make_node<ast::Jump>(loc,
                                               ast::JumpType::RETURN,
                                               std::move(expr));
        stmts.emplace_back(jump);
      }
      skip_whitespace();
      continue;
    }
    // Discard expression: _ = expr;
    if (peek() == '_') {
      // Check if next non-ws after '_' is '='
      size_t p = pos_ + 1;
      while (p < input_->size() && std::isspace((*input_)[p]))
        p++;
      if (p < input_->size() && (*input_)[p] == '=' &&
          (p + 1 >= input_->size() || (*input_)[p + 1] != '=')) {
        int sl = line_, sc = col_;
        advance(); // consume '_'
        skip_whitespace();
        advance(); // consume '='
        auto expr = parse_expression();
        auto loc = make_loc(sl, sc, line_, col_);
        match(';');
        auto *discard = ctx_.make_node<ast::DiscardExpr>(loc, std::move(expr));
        stmts.emplace_back(discard);
        skip_whitespace();
        continue;
      }
    }
    // Check if this is a statement (assignment/let) or an expression.
    if (check_keyword("let")) {
      auto stmt = parse_statement();
      stmts.push_back(std::move(stmt));
    } else if (peek() == '$' || peek() == '@') {
      // Could be an assignment statement or an expression.
      // Save position so we can backtrack if this is a trailing expression.
      size_t save = pos_;
      int sl = line_, sc = col_;
      auto stmt = parse_statement();
      skip_whitespace();
      if (allow_trailing_expr && peek() == '}') {
        // Check if this was just an expression (not an assignment).
        // If so, it could be a trailing expression.
        auto *es = stmt.as<ast::ExprStatement>();
        if (es) {
          // Backtrack and parse as expression for trailing expr.
          pos_ = save;
          line_ = sl;
          col_ = sc;
          auto expr = parse_expression();
          skip_whitespace();
          if (peek() == '}') {
            trailing_expr = std::move(expr);
          } else {
            // Expression was followed by ';', not '}', so it's a
            // statement, not a trailing expression. Consume the ';'.
            match(';');
            normalize_block(expr);
            auto loc = make_loc(sl, sc, line_, col_);
            auto *expr_stmt = ctx_.make_node<ast::ExprStatement>(
                loc, std::move(expr));
            stmts.emplace_back(expr_stmt);
          }
        } else {
          stmts.push_back(std::move(stmt));
        }
      } else {
        stmts.push_back(std::move(stmt));
      }
    } else {
      auto expr_pos = get_current_line_col();
      auto expr = parse_expression();
      skip_whitespace();

      if (peek() == ';') {
        advance(); // consume ';'
        normalize_block(expr);
        auto loc = make_loc(expr_pos.line, expr_pos.col, line_, col_);
        auto *expr_stmt = ctx_.make_node<ast::ExprStatement>(loc,
                                                             std::move(expr));
        stmts.emplace_back(expr_stmt);
      } else if (peek() == '}') {
        // No semicolon before closing brace: trailing expression.
        trailing_expr = std::move(expr);
      } else {
        // No semicolon but not at end of block (e.g. if/else).
        normalize_block(expr);
        auto loc = make_loc(expr_pos.line, expr_pos.col, line_, col_);
        auto *expr_stmt = ctx_.make_node<ast::ExprStatement>(loc,
                                                             std::move(expr));
        stmts.emplace_back(expr_stmt);
      }
    }
    // If nothing was consumed, skip to avoid an infinite loop.
    if (pos_ == before) {
      error("unexpected input in block");
      advance();
    }
    skip_whitespace();
  }

  if (!expect('}'))
    return nullptr;

  auto loc = make_loc(saved_line_col.line, saved_line_col.col, line_, col_);

  if (trailing_expr) {
    if (allow_trailing_expr) {
      return ctx_.make_node<ast::BlockExpr>(loc,
                                            std::move(stmts),
                                            std::move(*trailing_expr));
    }
    // Normalize nested block expressions before converting to statement.
    normalize_block(*trailing_expr);
    // Convert trailing expression to a statement (none_block semantics).
    auto *expr_stmt = ctx_.make_node<ast::ExprStatement>(
        loc, std::move(*trailing_expr));
    stmts.emplace_back(expr_stmt);
  }
  auto *none = ctx_.make_node<ast::None>(loc);
  return ctx_.make_node<ast::BlockExpr>(loc,
                                        std::move(stmts),
                                        ast::Expression(none));
}

ast::StatementImport *RDParser::parse_statement_import()
{
  int start_line = line_;
  int start_col = col_;
  if (!match("import")) {
    error("expected 'import'");
    return nullptr;
  }

  skip_whitespace();
  if (peek() != '"') {
    error("expected string after 'import'");
    return nullptr;
  }
  auto path = consume_string();
  auto loc = make_loc(start_line, start_col, line_, col_);
  match(';');

  return ctx_.make_node<ast::StatementImport>(loc, std::move(path));
}

ast::Statement RDParser::parse_while_or_unroll()
{
  int start_line = line_;
  int start_col = col_;
  bool is_while = check_keyword("while");
  if (is_while)
    match("while");
  else
    match("unroll");

  auto cond = parse_unary();
  auto *block = parse_block(false);
  auto loc = make_loc(start_line, start_col, line_, col_);

  if (is_while) {
    auto *w = ctx_.make_node<ast::While>(loc, std::move(cond), block);
    return { w };
  }
  auto *u = ctx_.make_node<ast::Unroll>(loc, std::move(cond), block);
  return { u };
}

ast::Statement RDParser::parse_for()
{
  int start_line = line_;
  int start_col = col_;
  match("for");

  bool has_parens = match('(');

  skip_whitespace();
  if (peek() != '$') {
    error("expected variable in for loop");
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto *none = ctx_.make_node<ast::None>(loc);
    auto *es = ctx_.make_node<ast::ExprStatement>(loc, ast::Expression(none));
    return { es };
  }
  int var_line = line_, var_col = col_;
  advance(); // consume '$'
  auto var_name = consume_identifier();
  auto var_loc = make_loc(var_line, var_col, line_, col_);
  auto *var = ctx_.make_node<ast::Variable>(var_loc, "$" + var_name);

  if (!expect(':')) {
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto *none = ctx_.make_node<ast::None>(loc);
    auto *es = ctx_.make_node<ast::ExprStatement>(loc, ast::Expression(none));
    return { es };
  }

  // Check if iterable is a range (expr..expr) or a map (@name).
  skip_whitespace();

  // Try to parse as a range or map. We parse a primary expression first,
  // then check if '..' follows (range) or not (map).
  auto first = parse_primary();
  skip_whitespace();

  // Check for range: first..end
  if (peek() == '.' && peek_next() == '.') {
    advance(); // first '.'
    advance(); // second '.'
    auto end = parse_primary();
    auto range_loc = make_loc(start_line, start_col, line_, col_);
    auto *range = ctx_.make_node<ast::Range>(range_loc,
                                             std::move(first),
                                             std::move(end));
    if (has_parens)
      expect(')');
    auto *block = parse_block(false);
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto *f = ctx_.make_node<ast::For>(loc, var, range, block);
    return { f };
  }

  // Must be a map.
  // The first expression should be a Map node.
  if (has_parens)
    expect(')');
  auto *block = parse_block(false);
  auto loc = make_loc(start_line, start_col, line_, col_);

  // Extract the Map* from the expression.
  auto *map_ptr = first.as<ast::Map>();
  if (!map_ptr) {
    error("expected map or range in for loop");
    auto *none = ctx_.make_node<ast::None>(loc);
    auto *es = ctx_.make_node<ast::ExprStatement>(loc, ast::Expression(none));
    return { es };
  }
  auto *f = ctx_.make_node<ast::For>(loc, var, map_ptr, block);
  return { f };
}

// Statement helpers

void RDParser::expect_stmt_end()
{
  skip_whitespace();
  if (peek() != '}')
    expect(';');
  else
    match(';');
}

// Try to match a compound assignment operator. Returns the base operator
// if found, or nullopt if not a compound assignment.
std::optional<ast::Operator> RDParser::try_compound_op()
{
  skip_whitespace();
  if (at_end())
    return std::nullopt;

  char c = peek();
  char next = peek_next();

  // Three-char operators
  if (c == '<' && next == '<' && pos_ + 2 < input_->size() &&
      (*input_)[pos_ + 2] == '=') {
    advance();
    advance();
    advance();
    return ast::Operator::LEFT;
  }
  if (c == '>' && next == '>' && pos_ + 2 < input_->size() &&
      (*input_)[pos_ + 2] == '=') {
    advance();
    advance();
    advance();
    return ast::Operator::RIGHT;
  }

  // Two-char operators
  if (next == '=') {
    switch (c) {
      case '+':
        advance();
        advance();
        return ast::Operator::PLUS;
      case '-':
        advance();
        advance();
        return ast::Operator::MINUS;
      case '*':
        advance();
        advance();
        return ast::Operator::MUL;
      case '/':
        advance();
        advance();
        return ast::Operator::DIV;
      case '%':
        advance();
        advance();
        return ast::Operator::MOD;
      case '&':
        advance();
        advance();
        return ast::Operator::BAND;
      case '|':
        advance();
        advance();
        return ast::Operator::BOR;
      case '^':
        advance();
        advance();
        return ast::Operator::BXOR;
      default:
        break;
    }
  }

  return std::nullopt;
}

ast::Statement RDParser::make_assignment_or_expr(ast::Expression lhs,
                                                 int stmt_line,
                                                 int stmt_col)
{
  skip_whitespace();

  // Simple assignment: lhs = expr
  if (peek() == '=' && peek_next() != '=') {
    advance();
    auto rhs = parse_expression();
    auto loc = make_loc(stmt_line, stmt_col, line_, col_);
    expect_stmt_end();
    auto *map = lhs.as<ast::Map>();
    auto *map_access = lhs.as<ast::MapAccess>();
    if (map) {
      auto *assign = ctx_.make_node<ast::AssignScalarMapStatement>(
          loc, map, std::move(rhs));
      return { assign };
    }
    if (map_access) {
      auto *assign = ctx_.make_node<ast::AssignMapStatement>(loc,
                                                             map_access,
                                                             std::move(rhs));
      return { assign };
    }
    // Must be a variable.
    auto *var = lhs.as<ast::Variable>();
    auto *assign = ctx_.make_node<ast::AssignVarStatement>(loc,
                                                           var,
                                                           std::move(rhs));
    return { assign };
  }

  // Compound assignment: lhs += expr etc.
  {
    size_t save = pos_;
    int sl = line_, sc = col_;
    auto compound = try_compound_op();
    if (compound) {
      auto rhs = parse_expression();
      auto op_loc = make_loc(sl, sc, line_, col_);
      auto *binop = ctx_.make_node<ast::Binop>(
          op_loc, lhs, *compound, std::move(rhs));
      auto loc = make_loc(stmt_line, stmt_col, line_, col_);
      expect_stmt_end();
      auto *map = lhs.as<ast::Map>();
      auto *map_access = lhs.as<ast::MapAccess>();
      if (map) {
        auto *assign = ctx_.make_node<ast::AssignScalarMapStatement>(
            loc, map, ast::Expression(binop));
        return { assign };
      }
      if (map_access) {
        auto *assign = ctx_.make_node<ast::AssignMapStatement>(
            loc, map_access, ast::Expression(binop));
        return { assign };
      }
      auto *var = lhs.as<ast::Variable>();
      auto *assign = ctx_.make_node<ast::AssignVarStatement>(
          loc, var, ast::Expression(binop));
      return { assign };
    }
    pos_ = save;
    line_ = sl;
    col_ = sc;
  }

  // Post-increment/decrement: lhs++ or lhs--
  if (peek() == '+' && peek_next() == '+') {
    advance();
    advance();
    auto loc = make_loc(stmt_line, stmt_col, line_, col_);
    match(';');
    auto *unop = ctx_.make_node<ast::Unop>(loc,
                                           std::move(lhs),
                                           ast::Operator::POST_INCREMENT);
    auto *es = ctx_.make_node<ast::ExprStatement>(loc, ast::Expression(unop));
    return { es };
  }
  if (peek() == '-' && peek_next() == '-') {
    advance();
    advance();
    auto loc = make_loc(stmt_line, stmt_col, line_, col_);
    match(';');
    auto *unop = ctx_.make_node<ast::Unop>(loc,
                                           std::move(lhs),
                                           ast::Operator::POST_DECREMENT);
    auto *es = ctx_.make_node<ast::ExprStatement>(loc, ast::Expression(unop));
    return { es };
  }

  // Not an assignment, treat as expression statement.
  // First apply postfix operators (e.g. $x[0], $x.field), then continue
  // parsing any remaining binary operators (e.g. $x[0] == 102).
  auto postfix = parse_postfix(std::move(lhs));
  // Check for assignment after postfix (e.g. $x.field = expr)
  skip_whitespace();
  if (peek() == '=' && peek_next() != '=') {
    advance();
    auto rhs = parse_expression();
    auto loc = make_loc(stmt_line, stmt_col, line_, col_);
    match(';');
    auto *var = postfix.as<ast::Variable>();
    if (var) {
      auto *assign = ctx_.make_node<ast::AssignVarStatement>(loc,
                                                             var,
                                                             std::move(rhs));
      return { assign };
    }
  }
  // Continue parsing as a full expression (binary ops, ternary, etc.).
  auto expr = parse_binary(0, std::move(postfix));
  auto loc = make_loc(stmt_line, stmt_col, line_, col_);
  match(';');
  auto *expr_stmt = ctx_.make_node<ast::ExprStatement>(loc, std::move(expr));
  return { expr_stmt };
}

ast::Statement RDParser::parse_statement()
{
  int stmt_line = line_;
  int stmt_col = col_;
  skip_whitespace();

  // Let statement: let $x; let $x = expr; let $x : type = expr;
  if (match("let")) {
    skip_whitespace();
    if (peek() != '$') {
      error("expected variable after 'let'");
      auto loc = make_loc(stmt_line, stmt_col, line_, col_);
      auto *none = ctx_.make_node<ast::None>(loc);
      auto *expr_stmt = ctx_.make_node<ast::ExprStatement>(
          loc, ast::Expression(none));
      return { expr_stmt };
    }
    int var_line = line_;
    int var_col = col_;
    advance(); // consume '$'
    auto var_name = consume_identifier();
    auto var_loc = make_loc(var_line, var_col, line_, col_);
    auto *var = ctx_.make_node<ast::Variable>(var_loc, "$" + var_name);

    // Check for optional type annotation.
    ast::Typeof *type_annotation = nullptr;
    skip_whitespace();
    if (peek() == ':') {
      advance(); // consume ':'
      type_annotation = parse_type_annotation();
    }

    skip_whitespace();
    if (peek() == '=') {
      // let $x = expr; or let $x : type = expr;
      advance();
      auto rhs = parse_expression();
      auto loc = make_loc(stmt_line, stmt_col, line_, col_);
      match(';');
      ast::VarDeclStatement *decl;
      if (type_annotation) {
        decl = ctx_.make_node<ast::VarDeclStatement>(var_loc,
                                                     var,
                                                     type_annotation);
      } else {
        decl = ctx_.make_node<ast::VarDeclStatement>(var_loc, var);
      }
      auto *assign = ctx_.make_node<ast::AssignVarStatement>(loc,
                                                             decl,
                                                             std::move(rhs));
      return { assign };
    }

    // let $x; or let $x : type;
    auto loc = make_loc(stmt_line, stmt_col, line_, col_);
    match(';');
    ast::VarDeclStatement *decl;
    if (type_annotation) {
      decl = ctx_.make_node<ast::VarDeclStatement>(loc, var, type_annotation);
    } else {
      decl = ctx_.make_node<ast::VarDeclStatement>(loc, var);
    }
    return { decl };
  }

  // Variable: $x = expr; or $x += expr; or $x++ etc.
  if (peek() == '$') {
    // Check for positional parameter ($N) or param count ($#).
    if (pos_ + 1 < input_->size() &&
        (std::isdigit((*input_)[pos_ + 1]) || (*input_)[pos_ + 1] == '#')) {
      // Not a variable — fall through to expression parsing.
      auto expr = parse_expression();
      auto loc = make_loc(stmt_line, stmt_col, line_, col_);
      match(';');
      auto *expr_stmt = ctx_.make_node<ast::ExprStatement>(loc,
                                                           std::move(expr));
      return { expr_stmt };
    }
    int var_line = line_, var_col = col_;
    advance(); // consume '$'
    auto var_name = consume_identifier();
    auto var_loc = make_loc(var_line, var_col, line_, col_);
    auto *var = ctx_.make_node<ast::Variable>(var_loc, "$" + var_name);
    return make_assignment_or_expr(ast::Expression(var), stmt_line, stmt_col);
  }

  // Map: @x = expr; or @x[key] = expr; or @x += expr; etc.
  if (peek() == '@') {
    int map_line = line_, map_col = col_;
    advance(); // consume '@'
    auto map_expr = parse_map_with_optional_keys(map_line, map_col);
    return make_assignment_or_expr(std::move(map_expr), stmt_line, stmt_col);
  }

  auto expr = parse_expression();
  auto loc = make_loc(stmt_line, stmt_col, line_, col_);
  match(';');
  auto *expr_stmt = ctx_.make_node<ast::ExprStatement>(loc, std::move(expr));
  return { expr_stmt };
}

// Type parsing

SizedType RDParser::parse_sized_type()
{
  auto name = consume_identifier();

  // struct/union/enum type
  if (name == "struct" || name == "union" || name == "enum") {
    auto type_name = consume_identifier();
    SizedType stype = ast::ident_to_sized_type(name + " " + type_name);
    skip_whitespace();
    while (peek() == '*') {
      advance();
      stype = CreatePointer(stype);
      skip_whitespace();
    }
    if (peek() == '[') {
      advance();
      auto int_str = consume_integer_str();
      auto res = util::to_uint(int_str, 0);
      expect(']');
      return CreateArray(res ? *res : 0, stype);
    }
    return stype;
  }

  if (name.empty()) {
    error("expected type name");
    return CreateNone();
  }

  // Known type name (e.g. "uint32", "string", "void")
  auto known = ident_to_type(name);
  if (known) {
    SizedType stype = *known;
    skip_whitespace();
    if (peek() == '[') {
      advance();
      skip_whitespace();
      uint64_t size = 0;
      if (peek() != ']') {
        auto int_str = consume_integer_str();
        auto res = util::to_uint(int_str, 0);
        size = res ? *res : 0;
      }
      expect(']');
      // For sized types (string, buffer, inet), [N] sets the type's
      // size parameter. For other types, [N] creates an array.
      if (stype.IsStringTy())
        stype = CreateString(size);
      else if (stype.IsBufferTy())
        stype = CreateBuffer(size);
      else if (stype.IsInetTy())
        stype = CreateInet(size);
      else
        stype = CreateArray(size, stype);
    }
    skip_whitespace();
    while (peek() == '*') {
      advance();
      stype = CreatePointer(stype);
      skip_whitespace();
    }
    return stype;
  }

  // Treat as a struct/typedef type.
  int ptr_level = 0;
  skip_whitespace();
  while (peek() == '*') {
    advance();
    ptr_level++;
    skip_whitespace();
  }
  return ast::ident_to_c_struct(name, ptr_level);
}

// Try to parse a type name. Returns the SizedType if successful, or
// std::nullopt if the next tokens don't look like a type (position is
// restored in that case).
std::optional<SizedType> RDParser::try_parse_sized_type()
{
  if (looks_like_type())
    return parse_sized_type();

  size_t save = pos_;
  int sl = line_, sc = col_;
  auto name = consume_identifier();
  auto known = ident_to_type(name);
  if (known)
    return *known;

  pos_ = save;
  line_ = sl;
  col_ = sc;
  return std::nullopt;
}

ast::Typeof *RDParser::parse_type_annotation()
{
  skip_whitespace();
  int start_line = line_;
  int start_col = col_;

  // typeof(expr_or_type)
  if (check_keyword("typeof")) {
    match("typeof");
    expect('(');
    skip_whitespace();

    auto stype = try_parse_sized_type();
    if (stype) {
      expect(')');
      auto loc = make_loc(start_line, start_col, line_, col_);
      return ctx_.make_node<ast::Typeof>(loc, *stype);
    }
    auto expr = parse_expression();
    expect(')');
    auto loc = make_loc(start_line, start_col, line_, col_);
    return ctx_.make_node<ast::Typeof>(loc, std::move(expr));
  }

  // Check if the next token looks like a type name. If so, parse as type.
  // Otherwise, parse as an expression (e.g. typeinfo(expr)).
  auto stype = try_parse_sized_type();
  if (stype) {
    auto loc = make_loc(start_line, start_col, line_, col_);
    return ctx_.make_node<ast::Typeof>(loc, *stype);
  }

  // Not a type — parse as expression.
  auto expr = parse_expression();
  auto loc = make_loc(start_line, start_col, line_, col_);
  return ctx_.make_node<ast::Typeof>(loc, std::move(expr));
}

// Expression grammar

ast::Expression RDParser::parse_expression()
{
  return parse_ternary();
}

// Ternary: expr ? expr : expr  or  expr ? : expr
ast::Expression RDParser::parse_ternary()
{
  auto expr = parse_binary(0);
  size_t save = pos_;
  int sl = line_, sc = col_;
  skip_whitespace();

  if (peek() == '?') {
    const auto &expr_begin = expr.loc()->current.begin;
    int start_line = expr_begin.line;
    int start_col = expr_begin.column;
    advance(); // consume '?'
    skip_whitespace();

    ast::Expression then_expr;
    if (peek() == ':') {
      // Short form: expr ?: expr (reuse condition as then value)
      advance(); // consume ':'
      auto else_expr = parse_ternary();
      auto loc = make_loc(start_line, start_col, line_, col_);
      auto *if_node = ctx_.make_node<ast::IfExpr>(
          loc, expr, expr, std::move(else_expr));
      return { if_node };
    }

    then_expr = parse_ternary();
    expect(':');
    auto else_expr = parse_ternary();
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto *if_node = ctx_.make_node<ast::IfExpr>(
        loc, expr, std::move(then_expr), std::move(else_expr));
    return { if_node };
  }

  pos_ = save;
  line_ = sl;
  col_ = sc;
  return expr;
}

namespace {

struct BinopInfo {
  ast::Operator op;
  int prec;
};

// Returns the operator and precedence for a binary operator token,
// or std::nullopt if the current position is not a binary operator.
std::optional<BinopInfo> get_binop(const std::string &input, size_t pos)
{
  if (pos >= input.size())
    return std::nullopt;

  char c = input[pos];
  char next = (pos + 1 < input.size()) ? input[pos + 1] : '\0';

  // Skip compound assignments — they are not binary ops in expression context.
  if (next == '=' && (c == '+' || c == '-' || c == '*' || c == '/' ||
                      c == '%' || c == '&' || c == '|' || c == '^'))
    return std::nullopt;
  // <<= and >>=
  if ((c == '<' && next == '<') || (c == '>' && next == '>')) {
    if (pos + 2 < input.size() && input[pos + 2] == '=')
      return std::nullopt;
  }

  // Two-character operators first.
  if (c == '|' && next == '|')
    return BinopInfo{ .op = ast::Operator::LOR, .prec = 1 };
  if (c == '&' && next == '&')
    return BinopInfo{ .op = ast::Operator::LAND, .prec = 2 };
  if (c == '=' && next == '=')
    return BinopInfo{ .op = ast::Operator::EQ, .prec = 6 };
  if (c == '!' && next == '=')
    return BinopInfo{ .op = ast::Operator::NE, .prec = 6 };
  if (c == '<' && next == '=')
    return BinopInfo{ .op = ast::Operator::LE, .prec = 7 };
  if (c == '>' && next == '=')
    return BinopInfo{ .op = ast::Operator::GE, .prec = 7 };
  if (c == '<' && next == '<')
    return BinopInfo{ .op = ast::Operator::LEFT, .prec = 8 };
  if (c == '>' && next == '>')
    return BinopInfo{ .op = ast::Operator::RIGHT, .prec = 8 };

  // Single-character operators.
  if (c == '|' && next != '|')
    return BinopInfo{ .op = ast::Operator::BOR, .prec = 3 };
  if (c == '^')
    return BinopInfo{ .op = ast::Operator::BXOR, .prec = 4 };
  if (c == '&' && next != '&')
    return BinopInfo{ .op = ast::Operator::BAND, .prec = 5 };
  if (c == '<' && next != '<' && next != '=')
    return BinopInfo{ .op = ast::Operator::LT, .prec = 7 };
  if (c == '>' && next != '>' && next != '=')
    return BinopInfo{ .op = ast::Operator::GT, .prec = 7 };
  if (c == '+' && next != '+')
    return BinopInfo{ .op = ast::Operator::PLUS, .prec = 9 };
  if (c == '-' && next != '-')
    return BinopInfo{ .op = ast::Operator::MINUS, .prec = 9 };
  if (c == '*')
    return BinopInfo{ .op = ast::Operator::MUL, .prec = 10 };
  if (c == '/') {
    // If '/' is followed (after whitespace) by '{', it's the end of a
    // predicate, not a division operator. This mirrors the bison lexer's
    // AFTER_DIV → ENDPRED disambiguation.
    size_t p = pos + 1;
    while (p < input.size() && std::isspace(input[p]))
      p++;
    if (p < input.size() && input[p] == '{')
      return std::nullopt;
    return BinopInfo{ .op = ast::Operator::DIV, .prec = 10 };
  }
  if (c == '%')
    return BinopInfo{ .op = ast::Operator::MOD, .prec = 10 };

  return std::nullopt;
}

int op_length(ast::Operator op)
{
  switch (op) {
    case ast::Operator::LOR:
    case ast::Operator::LAND:
    case ast::Operator::EQ:
    case ast::Operator::NE:
    case ast::Operator::LE:
    case ast::Operator::GE:
    case ast::Operator::LEFT:
    case ast::Operator::RIGHT:
      return 2;
    default:
      return 1;
  }
}

} // namespace

// Precedence-climbing binary expression parser.
ast::Expression RDParser::parse_binary(int min_prec)
{
  return parse_binary(min_prec, parse_unary());
}

ast::Expression RDParser::parse_binary(int min_prec, ast::Expression left)
{
  while (true) {
    size_t save = pos_;
    int sl = line_, sc = col_;
    skip_whitespace();
    auto info = get_binop(*input_, pos_);
    if (!info || info->prec < min_prec) {
      pos_ = save;
      line_ = sl;
      col_ = sc;
      break;
    }

    const auto &left_begin = left.loc()->current.begin;
    int len = op_length(info->op);
    for (int i = 0; i < len; i++)
      advance();

    auto right = parse_binary(info->prec + 1);
    auto loc = make_loc(left_begin.line, left_begin.column, line_, col_);
    auto *binop = ctx_.make_node<ast::Binop>(
        loc, std::move(left), info->op, std::move(right));
    left = ast::Expression(binop);
  }

  return left;
}

// Unary prefix expressions: *expr, -expr, !expr, ~expr, ++var, --var
ast::Expression RDParser::parse_unary()
{
  skip_whitespace();
  int start_line = line_;
  int start_col = col_;

  // Pre-increment: ++var or ++@map
  if (peek() == '+' && peek_next() == '+') {
    advance();
    advance();
    auto expr = parse_unary();
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto *unop = ctx_.make_node<ast::Unop>(loc,
                                           std::move(expr),
                                           ast::Operator::PRE_INCREMENT);
    return { unop };
  }

  // Pre-decrement: --var or --@map
  if (peek() == '-' && peek_next() == '-') {
    advance();
    advance();
    auto expr = parse_unary();
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto *unop = ctx_.make_node<ast::Unop>(loc,
                                           std::move(expr),
                                           ast::Operator::PRE_DECREMENT);
    return { unop };
  }

  // Address-of: &$var or &@map
  if (peek() == '&') {
    advance();
    skip_whitespace();
    if (peek() == '$') {
      int var_line = line_, var_col = col_;
      advance();
      auto var_name = consume_identifier();
      auto var_loc = make_loc(var_line, var_col, line_, col_);
      auto *var = ctx_.make_node<ast::Variable>(var_loc, "$" + var_name);
      auto loc = make_loc(start_line, start_col, line_, col_);
      auto *addr = ctx_.make_node<ast::VariableAddr>(loc, var);
      return { addr };
    }
    if (peek() == '@') {
      int map_line = line_, map_col = col_;
      advance();
      auto map_name = consume_identifier();
      auto map_loc = make_loc(map_line, map_col, line_, col_);
      auto *map = ctx_.make_node<ast::Map>(map_loc, "@" + map_name);
      auto loc = make_loc(start_line, start_col, line_, col_);
      auto *addr = ctx_.make_node<ast::MapAddr>(loc, map);
      return { addr };
    }
    // & without $ or @ — parse as BAND unary (unlikely but safe fallback)
    auto expr = parse_unary();
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto *unop = ctx_.make_node<ast::Unop>(loc,
                                           std::move(expr),
                                           ast::Operator::BAND);
    return { unop };
  }

  ast::Operator op;
  if (peek() == '*') {
    op = ast::Operator::MUL;
  } else if (peek() == '!' &&
             (pos_ + 1 >= input_->size() || (*input_)[pos_ + 1] != '=')) {
    op = ast::Operator::LNOT;
  } else if (peek() == '~') {
    op = ast::Operator::BNOT;
  } else if (peek() == '-' &&
             (pos_ + 1 >= input_->size() || (*input_)[pos_ + 1] != '-')) {
    op = ast::Operator::MINUS;
  } else {
    return parse_postfix(parse_primary());
  }

  advance();
  auto expr = parse_unary();
  auto loc = make_loc(start_line, start_col, line_, col_);
  auto *unop = ctx_.make_node<ast::Unop>(loc, std::move(expr), op);
  return { unop };
}

// Postfix operations: .field, ->field, .N (tuple), [expr], ++, --
ast::Expression RDParser::parse_postfix(ast::Expression expr)
{
  while (true) {
    // Save position before whitespace lookahead so we don't advance
    // past the end of the expression when no postfix op is found.
    size_t save = pos_;
    int sl = line_, sc = col_;
    skip_whitespace();
    const auto &expr_begin = expr.loc()->current.begin;
    int start_line = expr_begin.line;
    int start_col = expr_begin.column;

    // Field access: expr.field or tuple access: expr.N
    if (peek() == '.') {
      // Make sure it's not '..' (range operator)
      if (peek_next() == '.')
        break;
      advance(); // consume '.'
      skip_whitespace();

      // Tuple access: expr.N
      if (std::isdigit(peek())) {
        auto int_str = consume_integer_str();
        auto res = util::to_uint(int_str, 0);
        auto loc = make_loc(start_line, start_col, line_, col_);
        auto *ta = ctx_.make_node<ast::TupleAccess>(
            loc, std::move(expr), static_cast<ssize_t>(res ? *res : 0));
        expr = ast::Expression(ta);
        continue;
      }

      // Field access: expr.field
      auto field = consume_identifier();
      if (field.empty()) {
        error("expected field name after '.'");
        break;
      }
      auto loc = make_loc(start_line, start_col, line_, col_);
      auto *fa = ctx_.make_node<ast::FieldAccess>(loc,
                                                  std::move(expr),
                                                  std::move(field));
      expr = ast::Expression(fa);
      continue;
    }

    // Arrow access: expr->field
    if (peek() == '-' && peek_next() == '>') {
      advance(); // '-'
      advance(); // '>'
      auto field = consume_identifier();
      if (field.empty()) {
        error("expected field name after '->'");
        break;
      }
      auto loc = make_loc(start_line, start_col, line_, col_);
      auto *fa = ctx_.make_node<ast::FieldAccess>(loc,
                                                  std::move(expr),
                                                  std::move(field));
      expr = ast::Expression(fa);
      continue;
    }

    // Array access: expr[index]
    if (peek() == '[') {
      advance(); // consume '['
      auto index = parse_expression();
      expect(']');
      auto loc = make_loc(start_line, start_col, line_, col_);
      auto *aa = ctx_.make_node<ast::ArrayAccess>(loc,
                                                  std::move(expr),
                                                  std::move(index));
      expr = ast::Expression(aa);
      continue;
    }

    // Post-increment: expr++
    if (peek() == '+' && peek_next() == '+') {
      advance();
      advance();
      auto loc = make_loc(start_line, start_col, line_, col_);
      auto *unop = ctx_.make_node<ast::Unop>(loc,
                                             std::move(expr),
                                             ast::Operator::POST_INCREMENT);
      expr = ast::Expression(unop);
      continue;
    }

    // Post-decrement: expr--
    if (peek() == '-' && peek_next() == '-') {
      advance();
      advance();
      auto loc = make_loc(start_line, start_col, line_, col_);
      auto *unop = ctx_.make_node<ast::Unop>(loc,
                                             std::move(expr),
                                             ast::Operator::POST_DECREMENT);
      expr = ast::Expression(unop);
      continue;
    }

    // No postfix op found — restore position to before whitespace.
    pos_ = save;
    line_ = sl;
    col_ = sc;
    break;
  }

  return expr;
}

// Primary expressions: atoms, calls, parenthesized/tuple/record exprs,
// if-expressions, sizeof, offsetof, typeinfo, comptime.
ast::Expression RDParser::parse_primary()
{
  skip_whitespace();
  int start_line = line_;
  int start_col = col_;

  // Parenthesized expression, cast, tuple, or record.
  if (peek() == '(') {
    return parse_paren_expr();
  }

  // If expression: if cond { expr } else { expr }
  if (match("if")) {
    auto cond = parse_unary();
    auto *then_block = parse_block();
    skip_whitespace();
    ast::Expression else_expr;
    if (match("else")) {
      skip_whitespace();
      if (peek() == '{') {
        auto *else_block = parse_block();
        else_expr = ast::Expression(else_block);
      } else if (check_keyword("if")) {
        // else if ...
        else_expr = parse_primary();
      } else {
        auto *else_block = parse_block();
        else_expr = ast::Expression(else_block);
      }
    } else {
      auto loc = make_loc(start_line, start_col, line_, col_);
      auto *none = ctx_.make_node<ast::None>(loc);
      else_expr = ast::Expression(none);
    }
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto *if_node = ctx_.make_node<ast::IfExpr>(
        loc, std::move(cond), then_block, std::move(else_expr));
    return { if_node };
  }

  // sizeof(type_or_expr)
  if (match("sizeof")) {
    expect('(');
    skip_whitespace();

    auto stype = try_parse_sized_type();
    if (stype) {
      expect(')');
      auto loc = make_loc(start_line, start_col, line_, col_);
      auto *s = ctx_.make_node<ast::Sizeof>(loc, *stype);
      return { s };
    }
    auto expr = parse_expression();
    expect(')');
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto *s = ctx_.make_node<ast::Sizeof>(loc, std::move(expr));
    return { s };
  }

  // offsetof(type, field.field...)
  if (match("offsetof")) {
    expect('(');
    skip_whitespace();

    // Try type first (struct Name)
    size_t save = pos_;
    int sl = line_, sc = col_;
    auto ident = consume_identifier();
    bool is_struct_type = (ident == "struct" || ident == "union" ||
                           ident == "enum");
    pos_ = save;
    line_ = sl;
    col_ = sc;

    if (is_struct_type) {
      auto stype = parse_sized_type();
      expect(',');
      auto fields = parse_field_list();
      expect(')');
      auto loc = make_loc(start_line, start_col, line_, col_);
      auto *o = ctx_.make_node<ast::Offsetof>(loc, stype, std::move(fields));
      return { o };
    }
    // Expression form: offsetof(expr, field)
    auto expr = parse_expression();
    expect(',');
    auto fields = parse_field_list();
    expect(')');
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto *o = ctx_.make_node<ast::Offsetof>(loc,
                                            std::move(expr),
                                            std::move(fields));
    return { o };
  }

  // typeinfo(type_or_expr)
  if (match("typeinfo")) {
    expect('(');
    auto *typeof_node = parse_type_annotation();
    expect(')');
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto *ti = ctx_.make_node<ast::Typeinfo>(loc, typeof_node);
    return { ti };
  }

  // comptime expr
  if (match("comptime")) {
    auto expr = parse_unary();
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto *ct = ctx_.make_node<ast::Comptime>(loc, std::move(expr));
    return { ct };
  }

  // Block expression: { stmts; expr }
  if (peek() == '{') {
    auto *block = parse_block();
    if (block) {
      return { block };
    }
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto *none = ctx_.make_node<ast::None>(loc);
    return { none };
  }

  // Try to read an identifier - could be a function call, builtin, or keyword.
  auto name = consume_identifier();
  if (!name.empty()) {
    auto name_loc = make_loc(start_line, start_col, line_, col_);

    // Boolean literals.
    if (name == "true" || name == "false") {
      auto *boolean = ctx_.make_node<ast::Boolean>(name_loc, name == "true");
      return { boolean };
    }

    skip_whitespace();
    if (peek() == '(') {
      return parse_call_expression(name, name_loc);
    }
    if (is_builtin(name)) {
      auto *builtin = ctx_.make_node<ast::Builtin>(name_loc, std::move(name));
      return { builtin };
    }
    // Just an identifier.
    auto *ident = ctx_.make_node<ast::Identifier>(name_loc, std::move(name));
    return { ident };
  }

  // Try a map (@name or @name[key]).
  if (peek() == '@') {
    advance(); // consume '@'
    return parse_map_with_optional_keys(start_line, start_col);
  }

  // Try a variable ($name), positional parameter ($N), or param count ($#).
  if (peek() == '$') {
    advance(); // consume '$'

    // $# → PositionalParameterCount
    if (peek() == '#') {
      advance();
      auto loc = make_loc(start_line, start_col, line_, col_);
      auto *ppc = ctx_.make_node<ast::PositionalParameterCount>(loc);
      return { ppc };
    }

    // $N → PositionalParameter
    if (std::isdigit(peek())) {
      std::string digits;
      while (!at_end() && std::isdigit(peek())) {
        digits += peek();
        advance();
      }
      auto loc = make_loc(start_line, start_col, line_, col_);
      try {
        long n = std::stol(digits);
        if (n < 1) {
          error("param $" + digits + " is out of integer range [1, " +
                    std::to_string(std::numeric_limits<long>::max()) + "]",
                start_line,
                start_col,
                line_,
                col_);
        }
        auto *pp = ctx_.make_node<ast::PositionalParameter>(loc, n);
        return { pp };
      } catch (...) {
        error("param $" + digits + " is out of integer range [1, " +
                  std::to_string(std::numeric_limits<long>::max()) + "]",
              start_line,
              start_col,
              line_,
              col_);
        auto *pp = ctx_.make_node<ast::PositionalParameter>(loc, 0);
        return { pp };
      }
    }

    // $name → Variable
    auto var_name = consume_identifier();
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto *var = ctx_.make_node<ast::Variable>(loc, "$" + var_name);
    return { var };
  }

  // Try an integer literal.
  if (std::isdigit(peek())) {
    auto int_str = consume_integer_str();
    auto res = util::to_uint(int_str, 0);
    if (!res) {
      std::stringstream ss;
      ss << res.takeError();
      error(ss.str(), start_line, start_col, line_, col_);
      auto loc = make_loc(start_line, start_col, line_, col_);
      auto *integer = ctx_.make_node<ast::Integer>(loc, 0);
      return { integer };
    }
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto *integer = ctx_.make_node<ast::Integer>(loc, *res, std::move(int_str));
    return { integer };
  }

  // Try a string literal.
  if (peek() == '"') {
    auto str = consume_string();
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto *string_node = ctx_.make_node<ast::String>(loc, std::move(str));
    return { string_node };
  }

  error("expected expression");
  auto loc = make_loc(start_line, start_col, line_, col_);
  auto *none = ctx_.make_node<ast::None>(loc);
  return { none };
}

// Parse parenthesized expressions, casts, tuples, and records.
ast::Expression RDParser::parse_paren_expr()
{
  int start_line = line_;
  int start_col = col_;

  // Save state for potential backtracking.
  size_t save_pos = pos_;
  auto saved_line_col = get_current_line_col();

  advance(); // consume '('
  skip_whitespace();

  // Empty tuple: ()
  if (peek() == ')') {
    advance();
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto *tuple = ctx_.make_node<ast::Tuple>(loc, ast::ExpressionList{});
    return { tuple };
  }

  // Check for record: (ident = expr, ...)
  // Look ahead: ident followed by '=' (not '==')
  {
    size_t p = pos_;
    // Skip whitespace already done above.
    if (std::isalpha((*input_)[p]) || (*input_)[p] == '_') {
      // Skip past identifier.
      size_t id_start = p;
      while (p < input_->size() &&
             (std::isalnum((*input_)[p]) || (*input_)[p] == '_'))
        p++;
      // Skip whitespace.
      while (p < input_->size() && std::isspace((*input_)[p]))
        p++;
      // Check for '=' not '=='
      if (p < input_->size() && (*input_)[p] == '=' &&
          (p + 1 >= input_->size() || (*input_)[p + 1] != '=')) {
        // Check that the identifier isn't a builtin (builtins are values).
        std::string ident(&(*input_)[id_start], (p - id_start));
        while (!ident.empty() && std::isspace(ident.back()))
          ident.pop_back();
        if (!is_builtin(ident)) {
          // Parse as record.
          ast::NamedArgumentList named_args;
          std::set<std::string> seen_names;
          bool record_error = false;
          do {
            skip_whitespace();
            int al = line_, ac = col_;
            auto arg_name = consume_identifier();
            if (arg_name.empty()) {
              error("expected identifier");
              record_error = true;
              break;
            }
            expect('=');
            auto arg_expr = parse_expression();
            auto arg_loc = make_loc(al, ac, line_, col_);
            if (seen_names.contains(arg_name)) {
              error("Named argument list already contains name: " + arg_name,
                    al,
                    ac,
                    line_,
                    col_);
            } else {
              seen_names.insert(arg_name);
            }
            named_args.push_back(ctx_.make_node<ast::NamedArgument>(
                arg_loc, std::move(arg_name), std::move(arg_expr)));
          } while (match(','));
          if (record_error) {
            // Skip to closing ')' to avoid cascading errors.
            int depth = 1;
            while (!at_end() && depth > 0) {
              if (peek() == '(')
                depth++;
              else if (peek() == ')')
                depth--;
              if (depth > 0)
                advance();
            }
          }
          expect(')');
          auto loc = make_loc(start_line, start_col, line_, col_);
          auto *record = ctx_.make_node<ast::Record>(loc,
                                                     std::move(named_args));
          return { record };
        }
      }
    }
    // Not a record — reset position (we only peeked).
    // pos_/line_/col_ haven't changed since we used raw p.
  }

  // Speculatively check if this looks like a cast.
  // (ident * ... *)expr  → always a cast (star disambiguates)
  // (ident)expr          → cast if followed by expression start
  // (typeof(...))expr    → always a cast
  bool looks_like_cast = false;
  if (std::isalpha(peek()) || peek() == '_') {
    // Skip past identifier.
    size_t p = pos_;
    while (p < input_->size() &&
           (std::isalnum((*input_)[p]) || (*input_)[p] == '_'))
      p++;

    // Check for typeof(...) pattern — typeof is always a type.
    std::string peeked_ident(&(*input_)[pos_], (p - pos_));
    if (peeked_ident == "typeof") {
      // Skip whitespace after "typeof".
      while (p < input_->size() && std::isspace((*input_)[p]))
        p++;
      // Skip past balanced parentheses.
      if (p < input_->size() && (*input_)[p] == '(') {
        int depth = 1;
        p++;
        while (p < input_->size() && depth > 0) {
          if ((*input_)[p] == '(')
            depth++;
          else if ((*input_)[p] == ')')
            depth--;
          p++;
        }
        // Skip whitespace and optional pointer stars.
        while (p < input_->size() && std::isspace((*input_)[p]))
          p++;
        while (p < input_->size() && (*input_)[p] == '*') {
          p++;
          while (p < input_->size() && std::isspace((*input_)[p]))
            p++;
        }
        if (p < input_->size() && (*input_)[p] == ')')
          looks_like_cast = true;
      }
    }

    // Skip whitespace.
    if (!looks_like_cast) {
      p = pos_;
      while (p < input_->size() &&
             (std::isalnum((*input_)[p]) || (*input_)[p] == '_'))
        p++;

      // Check if this is a multi-word type: struct/union/enum Name
      std::string first_word(&(*input_)[pos_], (p - pos_));
      if (first_word == "struct" || first_word == "union" ||
          first_word == "enum") {
        // Skip whitespace after keyword.
        while (p < input_->size() && std::isspace((*input_)[p]))
          p++;
        // Skip past type name.
        while (p < input_->size() &&
               (std::isalnum((*input_)[p]) || (*input_)[p] == '_'))
          p++;
      }

      while (p < input_->size() && std::isspace((*input_)[p]))
        p++;

      // Skip optional array size: [N]
      if (p < input_->size() && (*input_)[p] == '[') {
        p++; // skip '['
        while (p < input_->size() && (*input_)[p] != ']')
          p++;
        if (p < input_->size())
          p++; // skip ']'
        while (p < input_->size() && std::isspace((*input_)[p]))
          p++;
      }
    }

    if (!looks_like_cast && p < input_->size() && (*input_)[p] == '*') {
      // Ident followed by '*' — skip past stars + whitespace.
      while (p < input_->size() && (*input_)[p] == '*') {
        p++;
        while (p < input_->size() && std::isspace((*input_)[p]))
          p++;
      }
      if (p < input_->size() && (*input_)[p] == ')')
        looks_like_cast = true;
    } else if (!looks_like_cast && p < input_->size() && (*input_)[p] == ')') {
      // (ident) — cast if followed by an expression start.
      // Builtins are values, not types, so (pid)*tid is multiplication.
      std::string ident_str(&(*input_)[pos_], (p - pos_));
      // Trim trailing whitespace from ident.
      while (!ident_str.empty() && std::isspace(ident_str.back()))
        ident_str.pop_back();
      if (!is_builtin(ident_str)) {
        size_t after_paren = p + 1;
        while (after_paren < input_->size() &&
               std::isspace((*input_)[after_paren]))
          after_paren++;
        if (after_paren < input_->size()) {
          char next_ch = (*input_)[after_paren];
          looks_like_cast = std::isdigit(next_ch) || next_ch == '$' ||
                            next_ch == '@' || next_ch == '"' ||
                            next_ch == '(' || next_ch == '-' ||
                            next_ch == '!' || next_ch == '~' ||
                            next_ch == '*' || std::isalpha(next_ch) ||
                            next_ch == '_';
        }
      }
    }
  }

  if (looks_like_cast) {
    // Parse the type using parse_type_annotation (reuses type map).
    auto *typeof_node = parse_type_annotation();
    expect(')');
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto cast_target = parse_unary();
    auto *cast = ctx_.make_node<ast::Cast>(loc,
                                           typeof_node,
                                           std::move(cast_target));
    return { cast };
  }

  // Not a cast or record — backtrack and parse as expression.
  pos_ = save_pos;
  line_ = saved_line_col.line;
  col_ = saved_line_col.col;
  advance(); // consume '('

  auto first = parse_expression();
  skip_whitespace();

  // Check for tuple: (expr, ...) or (expr,)
  if (peek() == ',') {
    advance(); // consume ','
    skip_whitespace();

    ast::ExpressionList elems;
    elems.push_back(std::move(first));

    // (expr,) — single-element tuple with trailing comma
    if (peek() == ')') {
      advance();
      auto loc = make_loc(start_line, start_col, line_, col_);
      auto *tuple = ctx_.make_node<ast::Tuple>(loc, std::move(elems));
      return { tuple };
    }

    // Multi-element tuple
    elems.push_back(parse_expression());
    while (match(',')) {
      skip_whitespace();
      if (peek() == ')')
        break; // trailing comma
      elems.push_back(parse_expression());
    }
    expect(')');
    auto loc = make_loc(start_line, start_col, line_, col_);
    auto *tuple = ctx_.make_node<ast::Tuple>(loc, std::move(elems));
    return { tuple };
  }

  // Simple parenthesized expression.
  expect(')');
  return first;
}

ast::Expression RDParser::parse_call_expression(
    const std::string &name,
    const ast::SourceLocation &start_loc)
{
  expect('(');

  ast::ExpressionList args;
  skip_whitespace();
  if (peek() != ')') {
    args.push_back(parse_expression());
    while (match(',')) {
      args.push_back(parse_expression());
    }
  }

  expect(')');

  auto loc = make_loc(
      start_loc.begin.line, start_loc.begin.column, line_, col_);
  auto *call = ctx_.make_node<ast::Call>(loc,
                                         std::string(name),
                                         std::move(args));
  return { call };
}

// Expression helpers

ast::Expression RDParser::parse_map_with_optional_keys(int start_line,
                                                       int start_col)
{
  auto map_name = consume_identifier(); // may be empty for anonymous map
  auto map_loc = make_loc(start_line, start_col, line_, col_);
  auto *map = ctx_.make_node<ast::Map>(map_loc, "@" + map_name);
  skip_whitespace();
  if (peek() != '[')
    return { map };

  advance(); // consume '['
  ast::ExpressionList keys;
  keys.push_back(parse_expression());
  while (match(',')) {
    keys.push_back(parse_expression());
  }
  expect(']');
  auto access_loc = make_loc(start_line, start_col, line_, col_);
  ast::Expression key_expr;
  if (keys.size() > 1) {
    auto *tuple = ctx_.make_node<ast::Tuple>(access_loc, std::move(keys));
    key_expr = ast::Expression(tuple);
  } else {
    key_expr = std::move(keys.back());
  }
  auto *map_access = ctx_.make_node<ast::MapAccess>(access_loc,
                                                    map,
                                                    std::move(key_expr));
  return { map_access };
}

std::vector<std::string> RDParser::parse_field_list()
{
  std::vector<std::string> fields;
  fields.push_back(consume_identifier());
  while (true) {
    skip_whitespace();
    if (match('.')) {
      fields.push_back(consume_identifier());
    } else {
      break;
    }
  }
  return fields;
}

// Lexer helpers

void RDParser::advance()
{
  if (at_end())
    return;
  if ((*input_)[pos_] == '\n') {
    line_++;
    col_ = 1;
  } else {
    col_++;
  }
  pos_++;
}

char RDParser::peek() const
{
  if (at_end())
    return '\0';
  return (*input_)[pos_];
}

char RDParser::peek_next() const
{
  if (pos_ + 1 >= input_->size())
    return '\0';
  return (*input_)[pos_ + 1];
}

bool RDParser::at_end() const
{
  return pos_ >= input_->size();
}

void RDParser::skip_whitespace()
{
  while (!at_end()) {
    if (std::isspace(peek())) {
      advance();
    } else if (peek() == '/' && pos_ + 1 < input_->size()) {
      if ((*input_)[pos_ + 1] == '/') {
        // Line comment: skip to end of line.
        while (!at_end() && peek() != '\n')
          advance();
      } else if ((*input_)[pos_ + 1] == '*') {
        // Block comment: skip to closing */.
        advance(); // '/'
        advance(); // '*'
        while (!at_end()) {
          if (peek() == '*' && pos_ + 1 < input_->size() &&
              (*input_)[pos_ + 1] == '/') {
            advance(); // '*'
            advance(); // '/'
            break;
          }
          advance();
        }
      } else {
        break;
      }
    } else {
      break;
    }
  }
}

bool RDParser::match(char c)
{
  skip_whitespace();
  if (peek() == c) {
    advance();
    return true;
  }
  return false;
}

bool RDParser::match(const std::string &s)
{
  skip_whitespace();
  if (pos_ + s.size() > input_->size())
    return false;
  for (size_t i = 0; i < s.size(); i++) {
    if ((*input_)[pos_ + i] != s[i])
      return false;
  }
  // Make sure the keyword isn't a prefix of a longer identifier.
  if (pos_ + s.size() < input_->size() &&
      (std::isalnum((*input_)[pos_ + s.size()]) ||
       (*input_)[pos_ + s.size()] == '_')) {
    return false;
  }
  for (size_t i = 0; i < s.size(); i++) {
    advance();
  }
  return true;
}

bool RDParser::check_keyword(const std::string &s) const
{
  size_t p = pos_;
  // Skip whitespace without advancing the real position.
  while (p < input_->size() && std::isspace((*input_)[p]))
    p++;
  if (p + s.size() > input_->size())
    return false;
  for (size_t i = 0; i < s.size(); i++) {
    if ((*input_)[p + i] != s[i])
      return false;
  }
  // Ensure it's not a prefix of a longer identifier.
  return !(p + s.size() < input_->size() &&
           (std::isalnum((*input_)[p + s.size()]) ||
            (*input_)[p + s.size()] == '_'));
}

bool RDParser::expect(char c)
{
  if (!match(c)) {
    error(std::string("expected '") + c + "'");
    return false;
  }
  return true;
}

std::string RDParser::consume_identifier()
{
  skip_whitespace();
  if (!std::isalpha(peek()) && peek() != '_')
    return "";
  std::string result;
  while (!at_end() && (std::isalnum(peek()) || peek() == '_')) {
    result += peek();
    advance();
  }
  return result;
}

std::string RDParser::consume_string()
{
  // Opening quote already confirmed by caller, consume it.
  advance();
  std::string result;
  while (!at_end() && peek() != '"') {
    if (peek() == '\n') {
      error("unterminated string");
      return result;
    }
    if (peek() == '\\') {
      advance();
      if (at_end()) {
        error("unterminated string");
        return result;
      }
      switch (peek()) {
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
          oct += peek();
          advance();
          for (int i = 0; i < 2 && !at_end() && peek() >= '0' && peek() <= '7';
               i++) {
            oct += peek();
            advance();
          }
          result += static_cast<char>(std::strtol(oct.c_str(), nullptr, 8));
          continue; // Already advanced past octal digits.
        }
        case 'x':
        case 'X': {
          advance();
          std::string hex;
          for (int i = 0; i < 2 && !at_end() && std::isxdigit(peek()); i++) {
            hex += peek();
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
          error(std::string("invalid escape character '\\") + peek() + "'");
          break;
      }
    } else {
      result += peek();
    }
    advance();
  }
  if (!at_end())
    advance(); // Closing quote.
  return result;
}

// Consume an integer literal as a raw string. Handles decimal, hex (0x...),
// exponent notation (NeM), underscore separators, and optional suffixes.
std::string RDParser::consume_integer_str()
{
  skip_whitespace();
  std::string result;

  // Hex prefix
  if (peek() == '0' && (peek_next() == 'x' || peek_next() == 'X')) {
    result += peek();
    advance();
    result += peek();
    advance();
    while (!at_end() && (std::isxdigit(peek()) || peek() == '_')) {
      result += peek();
      advance();
    }
    return result;
  }

  // Decimal digits with possible underscores
  while (!at_end() && (std::isdigit(peek()) || peek() == '_')) {
    result += peek();
    advance();
  }

  // Exponent notation: e.g. 1e6
  if (!at_end() && (peek() == 'e' || peek() == 'E')) {
    result += peek();
    advance();
    while (!at_end() && (std::isdigit(peek()) || peek() == '_')) {
      result += peek();
      advance();
    }
  }

  // Optional suffix (u, l, ll, ul, ull, ns, us, ms, s, m, h, d)
  if (!at_end()) {
    // Check for time/size suffixes: ns, us, ms
    if ((peek() == 'n' || peek() == 'u' || peek() == 'm') &&
        pos_ + 1 < input_->size() && (*input_)[pos_ + 1] == 's') {
      result += peek();
      advance();
      result += peek();
      advance();
    } else if (peek() == 's' || peek() == 'm' || peek() == 'h' ||
               peek() == 'd') {
      result += peek();
      advance();
    } else if (peek() == 'u' || peek() == 'U') {
      result += peek();
      advance();
      // Possible 'l' or 'll' after 'u'
      if (!at_end() && (peek() == 'l' || peek() == 'L')) {
        result += peek();
        advance();
        if (!at_end() && (peek() == 'l' || peek() == 'L')) {
          result += peek();
          advance();
        }
      }
    } else if (peek() == 'l' || peek() == 'L') {
      result += peek();
      advance();
      if (!at_end() && (peek() == 'l' || peek() == 'L')) {
        result += peek();
        advance();
      }
    }
  }

  return result;
}

// Error reporting

void RDParser::error(const std::string &msg)
{
  // Compute the span of the current token for underline display.
  // Skip whitespace to find where the token starts.
  size_t p = pos_;
  while (p < input_->size() && std::isspace((*input_)[p]))
    p++;

  int begin_line = line_;
  int begin_col = col_;
  // Adjust for any whitespace we skipped.
  {
    size_t tmp = pos_;
    int tl = line_, tc = col_;
    while (tmp < p) {
      if ((*input_)[tmp] == '\n') {
        tl++;
        tc = 1;
      } else {
        tc++;
      }
      tmp++;
    }
    begin_line = tl;
    begin_col = tc;
  }

  // Find the end of the current token.
  size_t token_start = p;
  if (p < input_->size()) {
    char c = (*input_)[p];
    if (std::isalpha(c) || c == '_') {
      // Identifier or keyword.
      while (p < input_->size() &&
             (std::isalnum((*input_)[p]) || (*input_)[p] == '_'))
        p++;
    } else if (std::isdigit(c)) {
      // Number.
      while (p < input_->size() &&
             (std::isalnum((*input_)[p]) || (*input_)[p] == '.'))
        p++;
    } else if (c == '@' || c == '$') {
      // Map or variable - include the sigil and name.
      p++;
      while (p < input_->size() &&
             (std::isalnum((*input_)[p]) || (*input_)[p] == '_'))
        p++;
    } else {
      // Single character token (operator, punctuation, etc.).
      p++;
    }
  }

  int end_col = begin_col + static_cast<int>(p - token_start);

  error(msg, begin_line, begin_col, begin_line, end_col);
}

void RDParser::error(const std::string &msg,
                     int begin_line,
                     int begin_col,
                     int end_line,
                     int end_col)
{
  auto loc = make_loc(begin_line, begin_col, end_line, end_col);
  ast::SourceLocation valid(ctx_.source());
  valid.begin = loc.begin;
  valid.end = loc.end;
  ctx_.state_->diagnostics_->addError(
      std::make_shared<ast::LocationChain>(std::move(valid)))
      << msg;
}

// Source location tracking

ast::SourceLocation RDParser::make_loc(int begin_line,
                                       int begin_col,
                                       int end_line,
                                       int end_col) const
{
  ast::SourceLocation loc(ctx_.source());
  loc.begin.line = begin_line;
  loc.begin.column = begin_col;
  loc.end.line = end_line;
  loc.end.column = end_col;
  return loc;
}

RDParser::LineCol RDParser::get_current_line_col()
{
  return { .line = line_, .col = col_ };
}

// Lookahead helpers

bool RDParser::is_builtin(const std::string &name)
{
  static const std::unordered_set<std::string> builtins = {
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
      std::all_of(name.begin() + 3, name.end(), ::isdigit)) {
    return true;
  }
  if (name.size() >= 5 && name.starts_with("sarg") &&
      std::all_of(name.begin() + 4, name.end(), ::isdigit)) {
    return true;
  }

  return false;
}

bool RDParser::looks_like_type() const
{
  size_t save = pos_;
  // Skip whitespace without advancing the real position.
  while (save < input_->size() && std::isspace((*input_)[save]))
    save++;
  // Read identifier (must start with alpha or underscore).
  size_t id_start = save;
  if (save >= input_->size() ||
      (!std::isalpha((*input_)[save]) && (*input_)[save] != '_'))
    return false;
  while (save < input_->size() &&
         (std::isalnum((*input_)[save]) || (*input_)[save] == '_'))
    save++;
  std::string ident(&(*input_)[id_start], (save - id_start));
  if (ident == "struct" || ident == "union" || ident == "enum")
    return true;
  // Builtins are values, not types — don't treat them as types even if
  // followed by '*' or '['.
  if (is_builtin(ident))
    return false;
  // Check for ident followed by '*' (pointer type). Bare identifiers
  // followed by ')' are parsed as expressions and resolved to types by
  // later passes.
  while (save < input_->size() && std::isspace((*input_)[save]))
    save++;
  if (save < input_->size() && (*input_)[save] == '*')
    return true;
  // Only treat ident followed by '[' as a type if it's a known type name
  // (e.g. "int32[4]", "string[64]"). Unknown identifiers followed by '['
  // are array access expressions (e.g. "exp[0]").
  if (save < input_->size() && (*input_)[save] == '[')
    return ident_to_type(ident).has_value();
  return false;
}

bool RDParser::looks_like_c_definition() const
{
  size_t p = pos_;
  while (p < input_->size() && std::isspace((*input_)[p]))
    p++;
  // Skip keyword (struct/union/enum).
  while (p < input_->size() && std::isalpha((*input_)[p]))
    p++;
  while (p < input_->size() && std::isspace((*input_)[p]))
    p++;
  // Skip optional name.
  if (p < input_->size() &&
      (std::isalpha((*input_)[p]) || (*input_)[p] == '_')) {
    while (p < input_->size() &&
           (std::isalnum((*input_)[p]) || (*input_)[p] == '_'))
      p++;
    while (p < input_->size() && std::isspace((*input_)[p]))
      p++;
  }
  return p < input_->size() && (*input_)[p] == '{';
}

} // namespace bpftrace
