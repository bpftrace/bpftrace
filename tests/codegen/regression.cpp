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

  auto ok = ast::PassManager()
                .put(*bpftrace)
                .add(ast::CreateSemanticPass())
                .add(ast::CreateResourcePass())
                .run(driver.ctx);
  ASSERT_TRUE(ok && driver.ctx.diagnostics().ok());

  ast::CodegenLLVM codegen(driver.ctx, *bpftrace);
  codegen.compile();
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
