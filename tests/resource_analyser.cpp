#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "ast/passes/field_analyser.h"
#include "ast/passes/resource_analyser.h"
#include "ast/passes/semantic_analyser.h"
#include "clang_parser.h"
#include "driver.h"
#include "mocks.h"

namespace bpftrace {
namespace test {
namespace resource_analyser {

using ::testing::_;

void test(BPFtrace &bpftrace,
          const std::string &input,
          bool expected_result = true)
{
  Driver driver(bpftrace);
  std::stringstream out;
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  ASSERT_EQ(driver.parse_str(input), 0);

  ast::FieldAnalyser fields(driver.root.get(), bpftrace, out);
  ASSERT_EQ(fields.analyse(), 0) << msg.str() << out.str();

  ClangParser clang;
  ASSERT_TRUE(clang.parse(driver.root.get(), bpftrace));

  ASSERT_EQ(driver.parse_str(input), 0);
  out.str("");
  ast::SemanticAnalyser semantics(driver.root.get(), bpftrace, out, false);
  ASSERT_EQ(semantics.analyse(), 0) << msg.str() << out.str();

  ast::ResourceAnalyser resource_analyser(driver.root.get(), out);
  auto resources_optional = resource_analyser.analyse();
  EXPECT_EQ(resources_optional.has_value(), expected_result)
      << msg.str() << out.str();
}

void test(const std::string &input, bool expected_result = true)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
  test(*bpftrace, input, expected_result);
}

TEST(resource_analyser, multiple_lhist_bounds_in_single_map)
{
  test("BEGIN { @[0] = lhist(0, 0, 100000, 1000); @[1] = lhist(0, 0, 100000, "
       "100); exit() }",
       false);
}

} // namespace resource_analyser
} // namespace test
} // namespace bpftrace
