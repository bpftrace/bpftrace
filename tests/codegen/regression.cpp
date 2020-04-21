#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "bpforc.h"
#include "bpftrace.h"
#include "clang_parser.h"
#include "codegen_llvm.h"
#include "driver.h"
#include "semantic_analyser.h"

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
  MockBPFfeature feature;
  ast::SemanticAnalyser semantics(driver.root_, *bpftrace, feature);
  ASSERT_EQ(semantics.analyse(), 0);
  ASSERT_EQ(semantics.create_maps(true), 0);
  ast::CodegenLLVM codegen(driver.root_, *bpftrace, feature);
  codegen.compile();
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
