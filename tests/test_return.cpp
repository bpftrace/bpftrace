#include "ast/passes/test_return.h"
#include "ast/passes/attachpoint_passes.h"
#include "ast_matchers.h"
#include "mocks.h"
#include "parser.h"
#include "gtest/gtest.h"

namespace bpftrace::test::test_return {

void test(const std::string &input,
          const Matcher<const ast::Probe &> &probe_matcher)
{
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace &bpftrace = *mock_bpftrace;
  bpftrace.run_tests_ = true;
  ast::ASTContext ast("stdin", input);
  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .put(get_mock_function_info())
                .add(CreateParsePass())
                .add(ast::CreateParseAttachpointsPass())
                .add(ast::CreateTestReturnPass())
                .run();

  std::stringstream out;
  ast.diagnostics().emit(out);
  ASSERT_TRUE(ok && ast.diagnostics().ok()) << out.str();
  EXPECT_THAT(ast, Program().WithProbe(probe_matcher));
}

// A non-zero return in a test probe is rewritten to `<expr> != 0 ? <line> : 0`
// Here the return is on line 2.
TEST(test_return, rewrite_return_in_test_probe)
{
  test("test:t {\n"
       "  return 1;\n"
       "}",
       Probe({ "test:t" },
             { Return(If(Binop(ast::Operator::NE, Integer(1), Integer(0)),
                         Integer(2),
                         Integer(0))) }));
}

TEST(test_return, no_rewrite_bare_return)
{
  test("test:t {\n"
       "  return;\n"
       "}",
       Probe({ "test:t" }, { Jump(ast::JumpType::RETURN).HasNoReturnValue() }));
}

TEST(test_return, ignore_non_test_probes)
{
  test("kprobe:f {\n"
       "  return 1;\n"
       "}",
       Probe({ "kprobe:f" }, { Return(Integer(1)) }));
}

} // namespace bpftrace::test::test_return
