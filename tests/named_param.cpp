#include "ast/passes/named_param.h"
#include "ast/passes/parser.h"
#include "ast/passes/printer.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::named_param {

using ::testing::HasSubstr;

void test(const std::string& input,
          const std::string& expected,
          const std::string& error = "")
{
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace& bpftrace = *mock_bpftrace;
  // The input provided here is embedded into an expression.
  ast::ASTContext ast("stdin", input);
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .add(CreateParsePass())
                .add(ast::CreateNamedParamsPass())
                .run();

  std::ostringstream out;
  ast::Printer printer(out);
  printer.visit(ast.root);
  ast.diagnostics().emit(out);

  if (error.empty()) {
    ASSERT_TRUE(ok && ast.diagnostics().ok()) << msg.str() << out.str();
    EXPECT_THAT(out.str(), HasSubstr(expected)) << msg.str() << out.str();
  } else {
    ASSERT_FALSE(ok && ast.diagnostics().ok()) << msg.str() << out.str();
    EXPECT_THAT(out.str(), HasSubstr(error)) << msg.str() << out.str();
  }
}

void test_error(const std::string& input, const std::string& error)
{
  test(input, "", error);
}

TEST(named_param, basic_checks)
{
  test("BEGIN { $a = getopt(\"hello\"); }", "map: hello");
  test("BEGIN { $a = getopt(\"hello\", 1); }", "map: hello");
  test("BEGIN { $a = getopt(\"hello\", true); }", "map: hello");
  test("BEGIN { $a = getopt(\"hello\", false); }", "map: hello");
  test(R"(BEGIN { $a = getopt("hello", "bye"); })", "map: hello");

  test_error("BEGIN { $a = getopt(10); }",
             "First argument to 'getopt' must be a string literal");
  test_error("BEGIN { $a = getopt(\"hello\", $a); }",
             "Second argument to 'getopt' must be a string literal, integer "
             "literal, or a boolean literal.");
  test_error("BEGIN { $a = getopt(\"hello\", banana); }",
             "Second argument to 'getopt' must be a string literal, integer "
             "literal, or a boolean literal.");
  test_error(
      R"(BEGIN { $a = getopt("hello", 1); $b = getopt("hello", "bye"); })",
      "Command line option 'hello' needs to have the same default value in all "
      "places it is used. Previous default value: 1");
}

} // namespace bpftrace::test::named_param
