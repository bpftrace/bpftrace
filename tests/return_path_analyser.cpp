#include "ast/passes/return_path_analyser.h"
#include "ast/passes/parser.h"
#include "ast/passes/semantic_analyser.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::return_path_analyser {

using ::testing::_;

void test(BPFtrace &bpftrace, const std::string &input, int expected_result = 0)
{
  ast::ASTContext ast("stdin", input);
  std::stringstream out;
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .add(ast::AllParsePasses())
                .add(ast::CreateSemanticPass())
                .add(ast::CreateReturnPathPass())
                .run();
  ast.diagnostics().emit(out);
  EXPECT_EQ(int(!ast.diagnostics().ok()), expected_result)
      << msg.str() << out.str();
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
