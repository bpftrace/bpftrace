#include "ast/passes/control_flow_analyser.h"
#include "ast/passes/parser.h"
#include "ast/passes/type_system.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::control_flow_analyser {

using ::testing::_;

void test(BPFtrace &bpftrace, const std::string &input, int expected_result = 0)
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

TEST(control_flow_analyser, simple_return)
{
  test("fn test(): int64 { $x = 0; return 0; }", 0);
}

TEST(control_flow_analyser, simple_no_return)
{
  test("fn test(): int64 { $x = 0; }", 1);
}

TEST(control_flow_analyser, if_else)
{
  test("fn test($x: int64): int64 {"
       "  if ($x > 0) { return 0; } else { return 1; }"
       "}",
       0);
}

TEST(control_flow_analyser, if_else_no_return)
{
  test("fn test($x: int64): int64 {"
       "  if ($x > 0) { return 0; } else { $x = 0; }"
       "}",
       1);
}

TEST(control_flow_analyser, if_without_else)
{
  test("fn test($x: int64): int64 { if ($x > 0) { return 0; } }", 1);
}

TEST(control_flow_analyser, while_loop)
{
  // This was previously allowed, but is no longer allowed. All loops
  // are treated equally, and therefore we require all paths to return
  // appropriately ahead of any folding, etc.
  test("fn test($x: int64): int64 { while ($x) { return 0; } }", 1);
}

TEST(control_flow_analyser, if_branches)
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

TEST(control_flow_analyser, if_branches_fail)
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

TEST(control_flow_analyser, void_return_type)
{
  test("fn test() : void {}", 0);
}

} // namespace bpftrace::test::control_flow_analyser
