#include "driver.h"

extern void set_source_string(const std::string *s);
extern int yylex_init(yyscan_t *scanner);
extern int yylex_destroy(yyscan_t yyscanner);

namespace bpftrace {

void Driver::parse(Parser::symbol_type first_token)
{
  // Reset state on every pass.
  loc.initialize();
  struct_type.clear();
  buffer.clear();

  // Push the start token, which indicates that exact context that we should
  // now be parsing.
  token.emplace(first_token);

  yyscan_t scanner;
  yylex_init(&scanner);
  Parser parser(*this, scanner);
  if (debug) {
    parser.set_debug_level(1);
  }
  set_source_string(&ctx.source_->contents);
  parser.parse();
  yylex_destroy(scanner);
}

ast::Program *Driver::parse_program()
{
  parse(Parser::make_START_PROGRAM(loc));
  if (std::holds_alternative<ast::Program *>(result)) {
    return std::get<ast::Program *>(result);
  }
  return nullptr;
}

std::optional<ast::Expression> Driver::parse_expr()
{
  parse(Parser::make_START_EXPR(loc));
  if (std::holds_alternative<ast::Expression>(result)) {
    return std::get<ast::Expression>(result);
  }
  return std::nullopt;
}

void Driver::error(const location &l, const std::string &m)
{
  // This path is normally not allowed, however we don't yet have nodes
  // constructed. Therefore, we add diagnostics directly via the private field.
  ctx.state_->diagnostics_->addError(ctx.wrap(l)) << m;
}

ast::Pass CreateParsePass(bool debug)
{
  return ast::Pass::create("parse", [debug](ast::ASTContext &ast, BPFtrace &b) {
    Driver driver(ast, debug);
    ast.root = driver.parse_program();

    // Before proceeding, ensure that the size of the AST isn't past prescribed
    // limits. This functionality goes back to 80642a994, where it was added in
    // order to prevent stack overflow during fuzzing. It traveled through the
    // passes and visitor pattern, and this is a final return to the simplest
    // possible form. It is not necessary to walk the full AST in order to
    // determine the number of nodes. This can be done before any passes.
    if (ast.diagnostics().ok()) {
      assert(ast.root != nullptr);
      auto node_count = ast.node_count();
      if (node_count > b.max_ast_nodes_) {
        ast.root->addError()
            << "node count (" << node_count << ") exceeds the limit ("
            << b.max_ast_nodes_ << ")";
      }
    }
  });
}

} // namespace bpftrace
