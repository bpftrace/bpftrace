#include "ast/passes/attachpoint_passes.h"
#include "arch/arch.h"
#include "btf_common.h"
#include "driver.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test {

namespace attachpoint_parser {

using ::testing::HasSubstr;

void test(const std::string& input, const std::string& error = "")
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
                .put(get_mock_function_info())
                .add(CreateParsePass())
                .add(ast::CreateParseAttachpointsPass())
                .run();

  std::ostringstream out;
  ast.diagnostics().emit(out);

  // Trim the prefix off the error, since it may come with a newline embedded
  // which will cause the test fail.
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

void test_error(const std::string& input, const std::string& error)
{
  test(input, error);
}

void test_uprobe_lang(const std::string& input, const std::string& lang = "")
{
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace& bpftrace = *mock_bpftrace;

  // Valid PID to ensure util function proceeds.
  bpftrace.procmon_ = std::make_unique<MockProcMon>(getpid());
  ast::ASTContext ast("stdin", input);

  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .put(get_mock_function_info())
                .add(CreateParsePass())
                .add(ast::CreateParseAttachpointsPass())
                .run();

  ASSERT_TRUE(ok && ast.diagnostics().ok());

  auto* ap = ast.root->probes.at(0)->attach_points.at(0);

  if (!lang.empty()) {
    ASSERT_EQ(ap->lang, lang);
  } else {
    ASSERT_TRUE(ap->lang.empty());
  }
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
}

TEST(attachpoint_parser, uprobe_lang)
{
  test_uprobe_lang("uprobe:main { 1 }");
  test_uprobe_lang("uprobe:cpp:main { 1 }", "cpp");
}

} // namespace attachpoint_parser

namespace attachpoint_checker {

using ::testing::HasSubstr;

void test(BPFtrace& bpftrace,
          const std::string& input,
          const std::string& error = "")
{
  // The input provided here is embedded into an expression.
  ast::ASTContext ast("stdin", input);
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  // N.B. No C macro or tracepoint expansion.
  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .put(get_mock_function_info())
                .add(CreateParsePass())
                .add(ast::CreateParseAttachpointsPass())
                .add(ast::CreateCheckAttachpointsPass())
                .run();

  std::ostringstream out;
  ast.diagnostics().emit(out);

  // See above.
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
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace& bpftrace = *mock_bpftrace;
  test(bpftrace, input);
}

void test_error(const std::string& input, std::string&& error = "ERROR")
{
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace& bpftrace = *mock_bpftrace;
  test(bpftrace, input, error);
}

void test_error(BPFtrace& bpftrace,
                const std::string& input,
                std::string&& error = "ERROR")
{
  test(bpftrace, input, error);
}

TEST(attachpoint_checker, uprobe)
{
  test("uprobe:/bin/sh:f { 1 }");
  test("u:/bin/sh:f { 1 }");
  test("uprobe:/bin/sh:0x10 { 1 }");
  test("u:/bin/sh:0x10 { 1 }");
  test("uprobe:/bin/sh:f+0x10 { 1 }");
  test("u:/bin/sh:f+0x10 { 1 }");
  test("uprobe:sh:f { 1 }");
  test("uprobe:/bin/sh:cpp:f { 1 }");
  test_error("uprobe:/notexistfile:f { 1 }");
  test_error("uprobe:notexistfile:f { 1 }");
  test_error("uprobe:/bin/sh:nolang:f { 1 }");

  test("uretprobe:/bin/sh:f { 1 }");
  test("ur:/bin/sh:f { 1 }");
  test("uretprobe:sh:f { 1 }");
  test("ur:sh:f { 1 }");
  test("uretprobe:/bin/sh:0x10 { 1 }");
  test("ur:/bin/sh:0x10 { 1 }");
  test("uretprobe:/bin/sh:cpp:f { 1 }");
  test_error("uretprobe:/notexistfile:f { 1 }");
  test_error("uretprobe:notexistfile:f { 1 }");
  test_error("uretprobe:/bin/sh:nolang:f { 1 }");
}

TEST(attachpoint_checker, kprobe)
{
  test("kprobe:f { 1 }");
  test("kretprobe:f { 1 }");
}

TEST(attachpoint_checker, usdt)
{
  test("usdt:/bin/sh:probe { 1 }");
  test("usdt:sh:probe { 1 }");
  test("usdt:/bin/sh:namespace:probe { 1 }");
  test_error("usdt:/notexistfile:namespace:probe { 1 }");
  test_error("usdt:notexistfile:namespace:probe { 1 }");
}

TEST(attachpoint_checker, begin_end_probes)
{
  test("begin { 1 }");
  test("begin { 1 } begin { 2 }");

  test("end { 1 }");
  test("end { 1 } end { 2 }");
}

TEST(attachpoint_checker, bench_probes)
{
  test("bench:a { 1 } bench:b { 2 }");
  test_error("bench: { 1 }", R"(
stdin:1:1-7: ERROR: bench probes must have a name
bench: { 1 }
~~~~~~
)");
  test_error("BENCH:a { 1 } BENCH:a { 2 }", R"(
stdin:1:15-22: ERROR: "a" was used as the name for more than one BENCH probe
BENCH:a { 1 } BENCH:a { 2 }
              ~~~~~~~
stdin:1:1-8: ERROR: this is the other instance
BENCH:a { 1 } BENCH:a { 2 }
~~~~~~~
)");
}

TEST(attachpoint_checker, self_probe)
{
  test("self:signal:SIGUSR1 { 1 }");

  test_error("self:signal:sighup { 1 }", R"(
stdin:1:1-19: ERROR: sighup is not a supported signal
self:signal:sighup { 1 }
~~~~~~~~~~~~~~~~~~
)");
  test_error("self:keypress:space { 1 }", R"(
stdin:1:1-20: ERROR: keypress is not a supported trigger
self:keypress:space { 1 }
~~~~~~~~~~~~~~~~~~~
)");
}

TEST(attachpoint_checker, tracepoint)
{
  test("tracepoint:category:event { 1 }");
}

TEST(attachpoint_checker, rawtracepoint)
{
  test("rawtracepoint:event_rt { 1 }");
  test("rawtracepoint:event_rt { arg0 }");
  test("rawtracepoint:vmlinux:event_rt { arg0 }");
}

TEST(attachpoint_checker, watchpoint_invalid_modes)
{
  if (arch::Host::Machine != arch::ARM64 &&
      arch::Host::Machine != arch::X86_64) {
    GTEST_SKIP() << "Watchpoint tests are only supported on ARM64 and X86_64";
  }

  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace& bpftrace = *mock_bpftrace;
  bpftrace.procmon_ = std::make_unique<MockProcMon>(123);

  if (arch::Host::Machine == arch::ARM64) {
    test(bpftrace, "watchpoint:0x1234:8:r { 1 }");
  } else {
    test_error(bpftrace, "watchpoint:0x1234:8:r { 1 }");
  }
  test_error(bpftrace, "watchpoint:0x1234:8:rx { 1 }");
  test_error(bpftrace, "watchpoint:0x1234:8:wx { 1 }");
  test_error(bpftrace, "watchpoint:0x1234:8:xw { 1 }");
  test_error(bpftrace, "watchpoint:0x1234:8:rwx { 1 }");
  test_error(bpftrace, "watchpoint:0x1234:8:xx { 1 }");
  test_error(bpftrace, "watchpoint:0x1234:8:b { 1 }");
}

TEST(attachpoint_checker, watchpoint_absolute)
{
  if (arch::Host::Machine != arch::ARM64 &&
      arch::Host::Machine != arch::X86_64) {
    GTEST_SKIP() << "Watchpoint tests are only supported on ARM64 and X86_64";
  }

  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace& bpftrace = *mock_bpftrace;
  bpftrace.procmon_ = std::make_unique<MockProcMon>(123);

  test(bpftrace, "watchpoint:0x1234:8:rw { 1 }");
  test_error(bpftrace, "watchpoint:0x1234:9:rw { 1 }");
  test_error(bpftrace, "watchpoint:0x0:8:rw { 1 }");
}

TEST(attachpoint_checker, profile)
{
  test("profile:hz:997 { 1 }");
  test("profile:s:10 { 1 }");
  test("profile:ms:100 { 1 }");
  test("profile:us:100 { 1 }");
  test_error("profile:unit:100 { 1 }");
}

TEST(attachpoint_checker, interval)
{
  test("interval:hz:997 { 1 }");
  test("interval:s:10 { 1 }");
  test("interval:ms:100 { 1 }");
  test("interval:us:100 { 1 }");
  test_error("interval:unit:100 { 1 }");
}

TEST(attachpoint_checker, hardware)
{
  test("hardware:cpu-cycles:100000000 { 1 }");
  test_error("hardware:tomato:100000000 { 1 }");

  // Wildcard
  test_error("hardware:*:100000000 { 1 }");
}

TEST(attachpoint_checker, software)
{
  test("software:cpu-clock:100000000 { 1 }");
  test_error("software:tomato:100000000 { 1 }");

  // Wildcard
  test_error("software:*:100000000 { 1 }");
}

} // namespace attachpoint_checker

} // namespace bpftrace::test
