#include "ast/passes/cli_opts.h"
#include "ast/passes/parser.h"
#include "ast/passes/printer.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::cli_opts {

using ::testing::HasSubstr;

void test(const std::unordered_map<std::string, std::string>& named_args,
          const std::string& input,
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
                .add(ast::CreateCLIOptsPass(named_args))
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

void test_error(const std::unordered_map<std::string, std::string>& named_args,
                const std::string& input,
                const std::string& error)
{
  test(named_args, input, "", error);
}

TEST(cli_opts, basic_checks)
{
  test({}, "BEGIN { $a = getopt(\"hello\"); }", "variable: $a\n   int: 0");
  test({}, "BEGIN { $a = getopt(\"hello\", 1); }", "variable: $a\n   int: 1");
  test({ { "hello", "true" } },
       "BEGIN { $a = getopt(\"hello\"); }",
       "variable: $a\n   int: 1");
  test({ { "hello", "on" } },
       "BEGIN { $a = getopt(\"hello\"); }",
       "variable: $a\n   int: 1");
  test({ { "hello", "false" } },
       "BEGIN { $a = getopt(\"hello\", 1); }",
       "variable: $a\n   int: 0");
  test({},
       R"(BEGIN { $a = getopt("hello", "bye"); })",
       "variable: $a\n   string: bye");
  test({ { "hello", "goodbye" } },
       R"(BEGIN { $a = getopt("hello", "bye"); })",
       "variable: $a\n   string: goodbye");
  test({ { "hello", "1" } },
       R"(BEGIN { $a = getopt("hello", "bye"); })",
       "variable: $a\n   string: 1");
  test({}, "BEGIN { $a = getopt(\"hello\", 10); }", "variable: $a\n   int: 10");
  test({ { "hello", "11" } },
       "BEGIN { $a = getopt(\"hello\", 10); }",
       "variable: $a\n   int: 11");
  test({ { "hello", "-1" } },
       "BEGIN { $a = getopt(\"hello\", 10); }",
       "variable: $a\n   signed int: -1");

  test_error({},
             "BEGIN { $a = getopt(10); }",
             "First argument to 'getopt' must be a string literal");
  test_error({},
             "BEGIN { $a = getopt(\"hello\", pid); }",
             "Second argument to 'getopt' must be a string or integer literal");
  test_error({ { "hello", "bye" } },
             "BEGIN { $a = getopt(\"hello\", 10); }",
             "Command line option 'hello' is expecting an integer. Got: bye");
  test_error({ { "hello", "1000000000000000000000000000000" } },
             "BEGIN { $a = getopt(\"hello\", 10); }",
             "Value for command line option 'hello' is out of range. Got: "
             "1000000000000000000000000000000");
  test_error(
      { { "hello", "bye" } },
      "BEGIN { $a = getopt(\"hello\"); }",
      "Command line option 'hello' is expecting a boolean (e.g. 1, 'true'). "
      "Got: hello");
}

} // namespace bpftrace::test::cli_opts
