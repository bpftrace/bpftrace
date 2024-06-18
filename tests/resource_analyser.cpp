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
          bool expected_result = true,
          RequiredResources *out_p = nullptr)
{
  Driver driver(bpftrace);
  std::stringstream out;
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  ASSERT_EQ(driver.parse_str(input), 0);

  ast::FieldAnalyser fields(driver.ctx.root, bpftrace, out);
  ASSERT_EQ(fields.analyse(), 0) << msg.str() << out.str();

  ClangParser clang;
  ASSERT_TRUE(clang.parse(driver.ctx.root, bpftrace));

  ASSERT_EQ(driver.parse_str(input), 0);
  out.str("");
  ast::SemanticAnalyser semantics(driver.ctx, bpftrace, out, false);
  ASSERT_EQ(semantics.analyse(), 0) << msg.str() << out.str();

  ast::ResourceAnalyser resource_analyser(driver.ctx.root, bpftrace, out);
  auto resources_optional = resource_analyser.analyse();
  EXPECT_EQ(resources_optional.has_value(), expected_result)
      << msg.str() << out.str();

  if (out_p)
    *out_p = *resources_optional;
}

void test(const std::string &input,
          bool expected_result = true,
          RequiredResources *out = nullptr)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
  return test(*bpftrace, input, expected_result, out);
}

TEST(resource_analyser, multiple_hist_bits_in_single_map)
{
  test("BEGIN { @ = hist(1, 1); @ = hist(1, 2); exit()}", false);
}

TEST(resource_analyser, multiple_lhist_bounds_in_single_map)
{
  test("BEGIN { @[0] = lhist(0, 0, 100000, 1000); @[1] = lhist(0, 0, 100000, "
       "100); exit() }",
       false);
}

TEST(resource_analyser, printf_in_subprog)
{
  test("fn greet(): void { printf(\"Hello, world\\n\"); }", true);
}

TEST(resource_analyser, fmt_string_args_size_ints)
{
  RequiredResources resources;
  test(R"(BEGIN { printf("%d %d", 3, 4) })", true, &resources);
  EXPECT_EQ(resources.max_fmtstring_args_size, 24);
}

TEST(resource_analyser, fmt_string_args_size_arrays)
{
  RequiredResources resources;
  test(
      R"(struct Foo { int a; char b[10]; } BEGIN { $foo = (struct Foo *)0; $foo2 = (struct Foo *)1; printf("%d %s %d %s\n", $foo->a, $foo->b, $foo2->a, $foo2->b) })",
      true,
      &resources);
  EXPECT_EQ(resources.max_fmtstring_args_size, 56);
}

TEST(resource_analyser, fmt_string_args_size_strings)
{
  RequiredResources resources;
  test(
      R"(BEGIN { printf("%dst: %sa; %dnd: %sb;; %drd: %sc;;; %dth: %sd;;;;\n", 1, "a", 2, "ab", 3, "abc", 4, "abcd") })",
      true,
      &resources);
  EXPECT_EQ(resources.max_fmtstring_args_size, 72);
}

TEST(resource_analyser, fmt_string_args_non_map_print_int)
{
  RequiredResources resources;
  test(R"(BEGIN { print(5) })", true, &resources);
  EXPECT_EQ(resources.max_fmtstring_args_size, 24);
}

TEST(resource_analyser, fmt_string_args_non_map_print_arr)
{
  RequiredResources resources;
  test(
      R"(struct Foo { char a[24]; } BEGIN { print(5); $foo = (struct Foo *)0; print($foo->a) })",
      true,
      &resources);
  EXPECT_EQ(resources.max_fmtstring_args_size, 40);
}

} // namespace resource_analyser
} // namespace test
} // namespace bpftrace
