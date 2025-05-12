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

  CDefinitions no_c_defs; // Output from clang parser.

  // N.B. No macros or tracepoint expansion.
  auto ok = ast::PassManager()
                .put(ast)
                .put<BPFtrace>(*bpftrace)
                .put(no_c_defs)
                .add(CreateParsePass())
                .add(ast::CreateResolveImportsPass({}))
                .add(ast::CreateParseAttachpointsPass())
                .add(ast::CreateFieldAnalyserPass())
                .add(ast::CreateMapSugarPass())
                .add(ast::CreateSemanticPass())
                .add(ast::CreateResourcePass())
                .add(ast::AllCompilePasses())
                .run();
  ASSERT_TRUE(ok && ast.diagnostics().ok());
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
