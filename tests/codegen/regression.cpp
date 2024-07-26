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
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
  ast::SemanticAnalyser semantics(driver.ctx, *bpftrace);
  ASSERT_EQ(semantics.analyse(), 0);

  ast::ResourceAnalyser resource_analyser(driver.ctx.root, *bpftrace);
  auto resources_optional = resource_analyser.analyse();
  ASSERT_TRUE(resources_optional.has_value());
  bpftrace->resources = resources_optional.value();

  ast::CodegenLLVM codegen(driver.ctx.root, *bpftrace);
  codegen.compile();
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
