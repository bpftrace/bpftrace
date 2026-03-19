#include "driver.h"

#include "rd_parser.h"

namespace bpftrace {

ast::Pass CreateParsePass(bool debug)
{
  return ast::Pass::create("parse", [=](ast::ASTContext &ast) {
    RDParser parser(ast, debug);
    ast.root = parser.parse();
  });
}

} // namespace bpftrace
