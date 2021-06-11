#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "ast/resource_analyser.h"
#include "ast/semantic_analyser.h"
#include "bpforc.h"
#include "bpftrace.h"
#include "clang_parser.h"
#include "codegen_llvm.h"
#include "driver.h"

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
  ast::SemanticAnalyser semantics(driver.root_, *bpftrace);
  ASSERT_EQ(semantics.analyse(), 0);

  ast::ResourceAnalyser resource_analyser(driver.root_);
  auto resources = resource_analyser.analyse();
  ASSERT_EQ(resources.create_maps(*bpftrace, true), 0);
  bpftrace->resources = resources;

  ast::CodegenLLVM codegen(driver.root_, *bpftrace);
  codegen.compile();
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
