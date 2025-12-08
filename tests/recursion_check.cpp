#include "ast/passes/recursion_check.h"
#include "ast/passes/attachpoint_passes.h"
#include "driver.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::recursion_check {

void test(const std::string& input, bool has_recursion_check)
{
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace& bpftrace = *mock_bpftrace;

  ast::ASTContext ast("stdin", input);

  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .put(get_mock_function_info())
                .add(CreateParsePass())
                .add(ast::CreateParseAttachpointsPass())
                .add(ast::CreateRecursionCheckPass())
                .run();
  ASSERT_TRUE(ok && ast.diagnostics().ok());
  EXPECT_EQ(bpftrace.need_recursion_check_, has_recursion_check);
}

TEST(recursion_check, has_check)
{
  test("fentry:vmlinux:queued_spin_lock_slowpath { 1 }", true);
  test("fentry:otherfunc, fentry:vmlinux:queued_spin_lock_slowpath { 1 }",
       true);
  test("fentry:otherfunc { 1 } fentry:vmlinux:queued_spin_lock_slowpath { 1 }",
       true);
  test("fentry:otherfunc { 1 }", false);
}

} // namespace bpftrace::test::recursion_check
