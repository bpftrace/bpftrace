#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "common.h"

namespace bpftrace::test::codegen {

using ::testing::_;

TEST(codegen, regression_957)
{
  ast::ASTContext ast("stdin",
                      "t:sched:sched_one* { cat(\"/proc/%d/maps\", pid); }");
  auto bpftrace = get_mock_bpftrace();

  ast::CDefinitions no_c_defs; // Output from clang parser.

  // N.B. No macros or tracepoint expansion.
  auto ok = ast::PassManager()
                .put(ast)
                .put<BPFtrace>(*bpftrace)
                .put(no_c_defs)
                .add(CreateParsePass())
                .add(ast::CreateResolveImportsPass())
                .add(ast::CreateImportInternalScriptsPass())
                .add(ast::CreateParseAttachpointsPass())
                .add(ast::CreateCheckAttachpointsPass())
                .add(ast::CreateControlFlowPass())
                .add(ast::CreateMacroExpansionPass())
                .add(ast::CreateApExpansionPass())
                .add(ast::CreateProbeExpansionPass())
                .add(ast::CreateFieldAnalyserPass())
                .add(ast::CreateNamedParamsPass())
                .add(ast::CreateMapSugarPass())
                .add(ast::CreateLLVMInitPass())
                .add(ast::CreateClangBuildPass())
                .add(ast::CreateProbeExpansionPass({ ProbeType::tracepoint }))
                .add(ast::CreateTypeSystemPass())
                .add(ast::CreateSemanticPass())
                .add(ast::CreateResourcePass())
                .add(ast::AllCompilePasses())
                .run();
  ASSERT_TRUE(ok && ast.diagnostics().ok());
}

} // namespace bpftrace::test::codegen
