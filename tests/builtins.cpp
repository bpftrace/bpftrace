#include "ast/passes/builtins.h"

#include "ast/passes/attachpoint_passes.h"
#include "driver.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::buitins {

using ::testing::HasSubstr;

void test(const std::string& input,
          bool features,
          const std::string& error = "")
{
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace& bpftrace = *mock_bpftrace;
  bpftrace.feature_ = std::make_unique<MockBPFfeature>(*mock_bpftrace->btf_,
                                                       features);

  // The input provided here is embedded into an expression.
  ast::ASTContext ast("stdin", input);
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .put(get_mock_function_info())
                .add(CreateParsePass())
                .add(ast::CreateParseAttachpointsPass())
                .add(ast::CreateBuiltinsPass())
                .run();

  std::ostringstream out;
  ast.diagnostics().emit(out);

  // Trim the prefix off the error since it may come with
  // a newline embedded which will cause the test fail.
  std::string trimmed_error = error;
  if (!error.empty()) {
    trimmed_error = error.substr(error.find_first_not_of("\n"));
  }

  if (trimmed_error.empty()) {
    ASSERT_TRUE(ok && ast.diagnostics().ok()) << msg.str() << out.str();
  } else {
    ASSERT_FALSE(ok && ast.diagnostics().ok()) << msg.str() << out.str();
    EXPECT_THAT(out.str(), HasSubstr(trimmed_error)) << msg.str() << out.str();
  }
}

void test(const std::string& input)
{
  test(input, true);
}

void test_error(const std::string& input, const std::string& error)
{
  test(input, true, error);
}

void test_error(const std::string& input,
                bool features,
                const std::string& error)
{
  test(input, features, error);
}

TEST(builtins, ctx)
{
  std::vector<std::string> valid = { "kprobe:k",
                                     "uprobe:sh:k",
                                     "kretprobe:k",
                                     "uretprobe:sh:k",
                                     "fentry:k",
                                     "fexit:k",
                                     "test:k",
                                     "rawtracepoint:k",
                                     "tracepoint:mod:k",
                                     "profile:s:10",
                                     "interval:s:10",
                                     "software:faults:1",
                                     "hardware:cpu-cycles:1",
                                     "watchpoint:0x1234:8:r",
                                     "iter:task",
                                     "begin",
                                     "end" };

  for (const auto& probe : valid) {
    test(probe + " { $x = ctx; }");
    test(probe + " { $x = args; }");
  }
}

TEST(builtins, argX)
{
  std::vector<std::string> valid = {
    "kprobe:k",
    "uprobe:sh:k",
    "usdt:sh:k",
  };

  for (const auto& probe : valid) {
    test(probe + " { $x = arg0; }");
  }
}

TEST(builtins, func)
{
  std::vector<std::string> valid = { "kprobe:k",
                                     "uprobe:sh:k",
                                     "kretprobe:k",
                                     "uretprobe:sh:k",
                                     "fentry:k",
                                     "fexit:k",
                                     "test:k",
                                     "rawtracepoint:k",
                                     "tracepoint:mod:k",
                                     "profile:s:10",
                                     "interval:s:10",
                                     "software:faults:1",
                                     "hardware:cpu-cycles:1",
                                     "watchpoint:0x1234:8:r",
                                     "iter:task",
                                     "begin",
                                     "end" };

  for (const auto& probe : valid) {
    test(probe + " { __builtin_func }");
  }
}

} // namespace bpftrace::test::buitins
