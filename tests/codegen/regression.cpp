#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

using ::testing::_;

TEST(codegen, regression_957)
{
  auto bpftrace = get_mock_bpftrace();
  Driver driver(*bpftrace);

  ASSERT_EQ(driver.parse_str("t:sched:sched_one* { cat(\"%s\", probe); }"), 0);
  ast::SemanticAnalyser semantics(driver.ctx, *bpftrace);
  semantics.analyse();
  ASSERT_TRUE(driver.ctx.diagnostics().ok());

  ast::ResourceAnalyser resource_analyser(*bpftrace);
  resource_analyser.visit(driver.ctx.root);
  bpftrace->resources = resource_analyser.resources();
  ASSERT_TRUE(driver.ctx.diagnostics().ok());

  ast::CodegenLLVM codegen(driver.ctx, *bpftrace);
  codegen.compile();
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
