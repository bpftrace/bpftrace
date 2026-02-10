#include "ast/passes/named_param.h"
#include "ast_matchers.h"
#include "driver.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::named_param {

using ::testing::_;
using ::testing::HasSubstr;

using bpftrace::test::AssignVarStatement;
using bpftrace::test::Boolean;
using bpftrace::test::Call;
using bpftrace::test::ExprStatement;
using bpftrace::test::Integer;
using bpftrace::test::Map;
using bpftrace::test::MapAccess;
using bpftrace::test::ProbeMatcher;
using bpftrace::test::Program;
using bpftrace::test::String;
using bpftrace::test::Variable;

template <typename MatcherT>
void test(const std::string& input,
          const MatcherT& matcher,
          const std::string& error = "")
{
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace& bpftrace = *mock_bpftrace;
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
  ast.diagnostics().emit(out);

  if (error.empty()) {
    ASSERT_TRUE(ok && ast.diagnostics().ok()) << msg.str() << out.str();
    EXPECT_THAT(ast, matcher);
  } else {
    ASSERT_FALSE(ok && ast.diagnostics().ok()) << msg.str() << out.str();
    EXPECT_THAT(out.str(), HasSubstr(error)) << msg.str() << out.str();
  }
}

void test_error(const std::string& input, const std::string& error)
{
  test(input, _, error);
}

TEST(named_param, basic_checks)
{
  test(R"(begin { $a = getopt("hello"); })",
       Program().WithProbe(ProbeMatcher().WithStatements({ AssignVarStatement(
           Variable("$a"), MapAccess(Map("hello"), Integer(0))) })));

  test(R"(begin { $a = getopt("hello", 1); })",
       Program().WithProbe(ProbeMatcher().WithStatements({ AssignVarStatement(
           Variable("$a"), MapAccess(Map("hello"), Integer(0))) })));

  test(R"(begin { $a = getopt("hello", true); })",
       Program().WithProbe(ProbeMatcher().WithStatements({ AssignVarStatement(
           Variable("$a"), MapAccess(Map("hello"), Integer(0))) })));

  test(R"(begin { $a = getopt("hello", false); })",
       Program().WithProbe(ProbeMatcher().WithStatements({ AssignVarStatement(
           Variable("$a"), MapAccess(Map("hello"), Integer(0))) })));

  test(R"(begin { $a = getopt("hello", "bye"); })",
       Program().WithProbe(ProbeMatcher().WithStatements({ AssignVarStatement(
           Variable("$a"), MapAccess(Map("hello"), Integer(0))) })));

  test_error(R"(begin { $a = getopt(10); })",
             "First argument to 'getopt' must be a string literal");
  test_error(R"(begin { $a = getopt("hello", $a); })",
             "Second argument to 'getopt' must be a string literal, integer "
             "literal, or a boolean literal.");
  test_error(R"(begin { $a = getopt("hello", banana); })",
             "Second argument to 'getopt' must be a string literal, integer "
             "literal, or a boolean literal.");
  test_error(
      R"(begin { $a = getopt("hello", 1); $b = getopt("hello", "bye"); })",
      "Command line option 'hello' needs to have the same default value in all "
      "places it is used. Previous default value: 1");
  test_error(
      R"(begin { $a = getopt("hello", 1, "Hello1"); $b = getopt("hello", 1, "Hello2"); })",
      "Command line option 'hello' must have the same description in all "
      "places it's used. Hint: You can wrap it in a macro");
}

} // namespace bpftrace::test::named_param
