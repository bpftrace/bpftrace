#include "ast/passes/builtins.h"

#include "arch/arch.h"
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
  std::vector<std::string> valid = {
    "uprobe:sh:k",           "uretprobe:sh:k",    "kprobe:k",
    "kretprobe:k",           "usdt:sh:k",         "profile:s:10",
    "interval:s:10",         "software:faults:1", "hardware:cpu-cycles:1",
    "watchpoint:0x1234:8:r", "iter:task"
  };

  for (const auto& probe : valid) {
    test(probe + " { $x = ctx; }");
  }

  test_error("tracepoint:mod:k { $x = ctx; }",
             "ERROR: Use args instead of ctx in tracepoint");

  std::vector<std::string> invalid = {
    "begin",
    "end",
    "test:k",
  };

  for (const auto& probe : invalid) {
    test_error(probe + " { $x = ctx; }",
               "ERROR: The ctx builtin can not be used");
  }
}

TEST(builtins, args)
{
  std::vector<std::string> valid = {
    "fentry:k", "fexit:k", "rawtracepoint:k", "uprobe:sh:k", "tracepoint:mod:k",
  };

  for (const auto& probe : valid) {
    test(probe + " { $x = args.foo; }");
  }

  test_error("iter:task { $x = args.foo; }", R"(
stdin:1:18-22: ERROR: The args builtin can only be used with tracepoint, rawtracepoint, fentry/fexit, and uprobe probes (iter used here)
iter:task { $x = args.foo; }
                 ~~~~
)");
  test_error(
      "fentry:bpf:fake_prog { $x = args.foo; }",
      "ERROR: The args builtin cannot be used for 'fentry/fexit:bpf' probes");

  std::vector<std::string> invalid = { "begin",
                                       "end",
                                       "test:k",
                                       "kprobe:k",
                                       "kretprobe:k",
                                       "uretprobe:sh:k",
                                       "usdt:sh:k",
                                       "profile:s:10",
                                       "interval:s:10",
                                       "software:faults:1",
                                       "hardware:cpu-cycles:1",
                                       "watchpoint:0x1234:8:r",
                                       "iter:task" };

  for (const auto& probe : invalid) {
    test_error(probe + " { $x = args.foo; }",
               "ERROR: The args builtin can only be used with "
               "tracepoint, rawtracepoint, fentry/fexit, and uprobe probes");
  }
}

TEST(builtins, retval)
{
  std::vector<std::string> valid = {
    "fentry:k", "fexit:k", "kretprobe:k", "uretprobe:sh:k"
  };

  for (const auto& probe : valid) {
    test(probe + " { __builtin_retval }");
  }

  test_error(
      "kretprobe:k { @map[0] = 1; for ($kv : @map) { __builtin_retval } }",
      "ERROR: '__builtin_retval' builtin is not allowed in a for-loop");
  test_error("iter:task { __builtin_retval }", R"(
stdin:1:13-29: ERROR: The retval builtin can only be used with 'kretprobe' and 'uretprobe' and 'fentry' probes
iter:task { __builtin_retval }
            ~~~~~~~~~~~~~~~~
)");

  std::vector<std::string> invalid = { "begin",
                                       "end",
                                       "test:k",
                                       "kprobe:k",
                                       "rawtracepoint:k",
                                       "uprobe:sh:k",
                                       "usdt:sh:k",
                                       "tracepoint:mod:k",
                                       "profile:s:10",
                                       "interval:s:10",
                                       "software:faults:1",
                                       "hardware:cpu-cycles:1",
                                       "watchpoint:0x1234:8:r",
                                       "iter:task" };

  for (const auto& probe : invalid) {
    test_error(probe + " { __builtin_retval }",
               "ERROR: The retval builtin can only be used with 'kretprobe' "
               "and 'uretprobe' and 'fentry' probes");
  }
}

TEST(builtins, argX)
{
  std::vector<std::string> valid = {
    "kprobe:k",
    "uprobe:sh:k",
    "usdt:sh:k",
    "rawtracepoint:k",
  };

  for (const auto& probe : valid) {
    test(probe + " { $x = arg0; $y = arg1; }");
  }

  test_error("kprobe:k { @map[0] = 1; for ($kv : @map) { $x = arg0; } }",
             "ERROR: 'arg0' builtin is not allowed in a for-loop");
  test_error("kprobe:k { $x = arg" +
                 std::to_string(arch::Host::arguments().size()) + "; }",
             "ERROR");
  test_error("begin { $x = arg0; }", R"(
stdin:1:14-18: ERROR: The arg0 builtin can only be used with 'kprobes', 'uprobes' and 'usdt' probes
begin { $x = arg0; }
             ~~~~
)");

  std::vector<std::string> invalid = { "begin",
                                       "end",
                                       "test:k",
                                       "kretprobe:k",
                                       "uretprobe:sh:k",
                                       "fentry:k",
                                       "fexit:k",
                                       "tracepoint:mod:k",
                                       "profile:s:10",
                                       "interval:s:10",
                                       "software:faults:1",
                                       "hardware:cpu-cycles:1",
                                       "watchpoint:0x1234:8:r",
                                       "iter:task" };

  for (const auto& probe : invalid) {
    test_error(probe + " { $x = arg0; }",
               "ERROR: The arg0 builtin can only be used with 'kprobes', "
               "'uprobes' and 'usdt' probes");
  }
}

TEST(builtins, func)
{
  std::vector<std::string> valid = { "kprobe:k",    "uprobe:sh:k",
                                     "kretprobe:k", "uretprobe:sh:k",
                                     "fentry:k",    "fexit:k" };

  for (const auto& probe : valid) {
    test(probe + " { __builtin_func }");
  }

  test_error("begin { __builtin_func }", R"(
stdin:1:9-23: ERROR: The func builtin can not be used with 'begin' probes
begin { __builtin_func }
        ~~~~~~~~~~~~~~
)");

  test_error("fexit:k { __builtin_func }", false, R"(
stdin:1:11-25: ERROR: BPF_FUNC_get_func_ip not available for your kernel version. Consider using the 'probe' builtin instead.
fexit:k { __builtin_func }
          ~~~~~~~~~~~~~~
)");

  std::vector<std::string> invalid = { "begin",
                                       "end",
                                       "test:k",
                                       "rawtracepoint:k",
                                       "tracepoint:mod:k",
                                       "profile:s:10",
                                       "interval:s:10",
                                       "software:faults:1",
                                       "hardware:cpu-cycles:1",
                                       "watchpoint:0x1234:8:r",
                                       "iter:task" };

  for (const auto& probe : invalid) {
    test_error(probe + " { __builtin_func }",
               "ERROR: The func builtin can not be used with");
  }
}

} // namespace bpftrace::test::buitins
