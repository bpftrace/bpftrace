#include "ast/attachpoint_parser.h"
#include "ast/passes/printer.h"
#include "btf_common.h"
#include "driver.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::attachpoint_parser {

using ::testing::HasSubstr;

void test(const std::string& input,
          bool listing = false,
          const std::string& error = "")
{
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace& bpftrace = *mock_bpftrace;

  // The input provided here is embedded into an expression.
  ast::ASTContext ast("stdin", input);
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  // N.B. No C macro or tracepoint expansion.
  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .add(CreateParsePass())
                .add(ast::CreateParseAttachpointsPass(listing))
                .run();

  std::ostringstream out;
  ast::Printer printer(out);
  printer.visit(ast.root);
  ast.diagnostics().emit(out);

  if (error.empty()) {
    ASSERT_TRUE(ok && ast.diagnostics().ok()) << msg.str() << out.str();
  } else {
    ASSERT_FALSE(ok && ast.diagnostics().ok()) << msg.str() << out.str();
    EXPECT_THAT(out.str(), HasSubstr(error)) << msg.str() << out.str();
  }
}

void test_error(const std::string& input, const std::string& error)
{
  test(input, false, error);
}

TEST(attachpoint_parser, iter)
{
  test("iter:task { 1 }");
  test("iter:task:pin { 1 }");
  test("iter:task { 2 } iter:task_file { 1 }");
  test_error("iter:task* { 1 }",
             R"(iter probe type does not support wildcards)");
  test_error("iter:task:* { 1 }",
             R"(iter probe type does not support wildcards)");
  test_error("iter:task, iter:task_file { 1 }",
             R"(iter probe only supports one attach point)");
  // Listing is ok
  test("iter:task* { 1 }", true);
  test("iter:task:* { 1 }", true);
  test("iter:task, iter:task_file { 1 }", true);
}

} // namespace bpftrace::test::attachpoint_parser
