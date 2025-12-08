#include "ast/passes/resource_analyser.h"
#include "ast/passes/parser.h"
#include "ast/passes/semantic_analyser.h"
#include "ast/passes/type_system.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::resource_analyser {

using ::testing::_;
using ::testing::ElementsAre;

void test(BPFtrace &bpftrace,
          const std::string &input,
          bool expected_result = true,
          RequiredResources *out_p = nullptr)
{
  ast::ASTContext ast("stdin", input);
  std::stringstream out;
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  ast::TypeMetadata no_types; // No external types defined.

  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .put(get_mock_function_info())
                .put(no_types)
                .add(ast::AllParsePasses())
                .add(ast::CreateSemanticPass())
                .add(ast::CreateResourcePass())
                .run();
  ASSERT_TRUE(bool(ok)) << msg.str();
  EXPECT_EQ(ast.diagnostics().ok(), expected_result) << msg.str();

  if (out_p)
    *out_p = std::move(bpftrace.resources);
}

void test(const std::string &input,
          bool expected_result = true,
          RequiredResources *out = nullptr,
          std::optional<uint64_t> on_stack_limit = std::nullopt)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->config_->on_stack_limit = on_stack_limit.value_or(0);

  test(*bpftrace, input, expected_result, out);
}

TEST(resource_analyser, multiple_hist_bits_in_single_map)
{
  test("begin { @ = hist(1, 1); @ = hist(1, 2); exit()}", false);
}

TEST(resource_analyser, multiple_lhist_bounds_in_single_map)
{
  test("begin { @[0] = lhist(0, 0, 100000, 1000); @[1] = lhist(0, 0, 100000, "
       "100); exit() }",
       false);
}

TEST(resource_analyser, printf_in_subprog)
{
  test(R"(fn greet(): void { printf("Hello, world\n"); })", true);
}

TEST(resource_analyser, fmt_string_args_size_ints)
{
  RequiredResources resources;
  test(R"(begin { printf("%d %d", 3, 4) })", true, &resources);
  EXPECT_EQ(resources.max_fmtstring_args_size, 16);
}

TEST(resource_analyser, fmt_string_args_below_on_stack_limit)
{
  RequiredResources resources;
  test(R"(begin { printf("%d %d", 3, 4) })", true, &resources, 32);
  EXPECT_EQ(resources.max_fmtstring_args_size, 0);
}

TEST(resource_analyser, fmt_string_args_size_arrays)
{
  RequiredResources resources;
  test(
      R"(struct Foo { int a; char b[10]; } begin { $foo = (struct Foo *)0; $foo2 = (struct Foo *)1; printf("%d %s %d %s\n", $foo->a, $foo->b, $foo2->a, $foo2->b) })",
      true,
      &resources);
  EXPECT_EQ(resources.max_fmtstring_args_size, 40);
}

TEST(resource_analyser, fmt_string_args_size_strings)
{
  RequiredResources resources;
  test(
      R"(begin { printf("%dst: %sa; %dnd: %sb;; %drd: %sc;;; %dth: %sd;;;;\n", 1, "a", 2, "ab", 3, "abc", 4, "abcd") })",
      true,
      &resources);
  EXPECT_EQ(resources.max_fmtstring_args_size, 32);
}

TEST(resource_analyser, fmt_string_args_non_map_print_int)
{
  RequiredResources resources;
  test(R"(begin { print(5) })", true, &resources);
  EXPECT_EQ(resources.max_fmtstring_args_size, 17);
}

TEST(resource_analyser, fmt_string_args_non_map_print_arr)
{
  RequiredResources resources;
  test(
      R"(struct Foo { char a[24]; } begin { print(5); $foo = (struct Foo *)0; print($foo->a) })",
      true,
      &resources);

  // See clang_parser.cpp; the increase signal well-formedness.
  EXPECT_EQ(resources.max_fmtstring_args_size, 40U + 1U);
}

TEST(resource_analyser, print_non_map_print_correct_args_order)
{
  RequiredResources resources;
  test(R"(begin { print({ $x = 1; print("bob"); $x > 1}) })", true, &resources);

  EXPECT_THAT(resources.non_map_print_args,
              ElementsAre(SizedType(Type::string, 4),
                          SizedType(Type::boolean, 1)));
}

} // namespace bpftrace::test::resource_analyser
