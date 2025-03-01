#include "ast/passes/parser.h"

#include "driver.h"
#include "ast/attachpoint_parser.h"

namespace bpftrace {
namespace ast {

Pass CreateParsePass(bool debug)
{
  return Pass::create("Parse", [](ASTContext &ast, BPFtrace& bpftrace) {
    Driver driver(ast, debug);
    ast.reset();
    driver.parse();

    // Before proceeding, ensure that the size of the AST isn't past prescribed
    // limits. This functionality goes back to 80642a994, where it was added in
    // order to prevent stack overflow during fuzzing. It traveled through the
    // passes and visitor pattern, and this is a final return to the simplest
    // possible form. It is not necessary to walk the full AST in order to
    // determine the number of nodes. This can be done before any passes.
    if (ast.diagnostics().ok()) {
      auto node_count = ast.node_count();
      if (node_count > bpftrace.max_ast_nodes_) {
        ast.root->addError() << "node count (" << node_count
                             << ") exceeds the limit (" << bpftrace.max_ast_nodes_
                             << ")";
      }
    }
  });
}

Pass CreateParseAttachpointPass()
{
  return Pass::create("ParseAttachpoints", [](ASTContext &ast, BPFtrace &b) {
    ast::AttachPointParser ap_parser(ast, bpftrace, false);
    ap_parser.parse();
  });
}

Pass CreateParseBTFPass()
{
  return Pass::create("ParseBTF", [](ASTContext &ast, BPFtrace& bpftrace) {
    bpftrace.parse_btf(bpftrace.list_modules(ast));
  });
}

Pass CreateParseTracepointFormatParsePass()
{
  return Pass::create("ParseBTF", [](ASTContext &ast, BPFtrace& bpftrace) {
    TracepointFormatParser::parse(ast, bpftrace);
  });
}

Pass CreateReparsePass()
{
  return Pass::create("Reparse", [](ASTContext &ast, Macros &macros) {
    ast.reset();
  });
}

} // namespace ast
} // namespace bpftrace
