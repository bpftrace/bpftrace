#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "ast/passes/field_analyser.h"
#include "ast/passes/return_path_analyser.h"
#include "ast/passes/semantic_analyser.h"
#include "clang_parser.h"
#include "driver.h"
#include "mocks.h"

namespace bpftrace::test::return_path_analyser {

using ::testing::_;

void test(BPFtrace &bpftrace, const std::string &input, int expected_result = 0)
{
  ast::ASTContext ast("stdin", input);
  Driver driver(ast, bpftrace);
  std::stringstream out;
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  driver.parse();
  ASSERT_TRUE(ast.diagnostics().ok()) << msg.str();

  ast::FieldAnalyser fields(bpftrace);
  fields.visit(ast.root);
  ASSERT_TRUE(ast.diagnostics().ok()) << msg.str();

  ClangParser clang;
  ASSERT_TRUE(clang.parse(ast.root, bpftrace));

  driver.parse();
  ASSERT_TRUE(ast.diagnostics().ok()) << msg.str();

  ast::SemanticAnalyser semantics(ast, bpftrace, false);
  semantics.analyse();
  ASSERT_TRUE(ast.diagnostics().ok()) << msg.str();

  ast::ReturnPathAnalyser return_path;
  return_path.visit(ast.root);
  ASSERT_EQ(int(!ast.diagnostics().ok()), expected_result) << msg.str();
}

void test(const std::string &input, int expected_result = 0)
{
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace, input, expected_result);
}

TEST(return_path_analyser, simple_return)
{
  test("fn test(): int64 { $x = 0; return 0; }", 0);
}

TEST(return_path_analyser, simple_no_return)
{
  test("fn test(): int64 { $x = 0; }", 1);
}

TEST(return_path_analyser, if_else)
{
  test("fn test($x: int64): int64 {"
       "  if ($x > 0) { return 0; } else { return 1; }"
       "}",
       0);
}

TEST(return_path_analyser, if_else_no_return)
{
  test("fn test($x: int64): int64 {"
       "  if ($x > 0) { return 0; } else { $x = 0; }"
       "}",
       1);
}

TEST(return_path_analyser, if_without_else)
{
  test("fn test($x: int64): int64 { if ($x > 0) { return 0; } }", 1);
}

TEST(return_path_analyser, while_loop)
{
  test("fn test($x: int64): int64 { while ($x) { return 0; } }", 1);
}

TEST(return_path_analyser, if_branches)
{
  test("fn test($x: int64): int64 {"
       "  if ($x > 0) {"
       "    if ($x > 0) { return 1; } else { return 0; }"
       "  } else {"
       "    if ($x > 0) { return 1; } else { return 0; }"
       "  }"
       "}",
       0);
}

TEST(return_path_analyser, if_branches_fail)
{
  test("fn test($x: int64): int64 {"
       "  if ($x > 0) {"
       "    if ($x > 0) { return 1; } else { return 0; }"
       "  } else {"
       "    if ($x > 0) { return 1; } else { $x = 1; }"
       "  }"
       "}",
       1);
}

TEST(return_path_analyser, void_return_type)
{
  test("fn test() : void {}", 0);
}

} // namespace bpftrace::test::return_path_analyser
