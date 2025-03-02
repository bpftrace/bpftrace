#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

using ::testing::_;

TEST(codegen, regression_957)
{
  ast::ASTContext ast("stdin", "t:sched:sched_one* { cat(\"%s\", probe); }");
  auto bpftrace = get_mock_bpftrace();
  Driver driver(ast, *bpftrace);

  driver.parse();
  ASSERT_TRUE(ast.diagnostics().ok());

  ast::AttachPointParser ap_parser(ast, *bpftrace, false);
  ap_parser.parse();
  ASSERT_TRUE(ast.diagnostics().ok());

  ast::SemanticAnalyser semantics(ast, *bpftrace);
  semantics.analyse();
  ASSERT_TRUE(ast.diagnostics().ok());

  ast::ResourceAnalyser resource_analyser(*bpftrace);
  resource_analyser.visit(ast.root);
  bpftrace->resources = resource_analyser.resources();
  ASSERT_TRUE(ast.diagnostics().ok());

  ast::CodegenLLVM codegen(ast, *bpftrace);
  codegen.compile();
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
