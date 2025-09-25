#include "ast/passes/attachpoint_passes.h"
#include "arch/arch.h"
#include "ast/passes/printer.h"
#include "btf_common.h"
#include "driver.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test {

namespace attachpoint_parser {

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

} // namespace attachpoint_parser

namespace attachpoint_checker {

using ::testing::HasSubstr;

void test(BPFtrace& bpftrace,
          const std::string& input,
          bool listing = false,
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
                .add(CreateParsePass())
                .add(ast::CreateParseAttachpointsPass(listing))
                .add(ast::CreateCheckAttachpointsPass(listing))
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

void test(const std::string& input, bool listing = false)
{
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace& bpftrace = *mock_bpftrace;
  test(bpftrace, input, listing);
}

void test_error(const std::string& input, std::string&& error = "ERROR")
{
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace& bpftrace = *mock_bpftrace;
  test(bpftrace, input, false, error);
}

void test_error(BPFtrace& bpftrace,
                const std::string& input,
                std::string&& error = "ERROR")
{
  test(bpftrace, input, false, error);
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
  test_error("begin { 1 } begin { 2 }");

  test("end { 1 }");
  test_error("end { 1 } end { 2 }");
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
stdin:1:14-22: ERROR: "a" was used as the name for more than one BENCH probe
BENCH:a { 1 } BENCH:a { 2 }
             ~~~~~~~~
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

TEST(attachpoint_checker, watchpoint_function)
{
  if (arch::Host::Machine != arch::ARM64 &&
      arch::Host::Machine != arch::X86_64) {
    GTEST_SKIP() << "Watchpoint tests are only supported on ARM64 and X86_64";
  }

  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace& bpftrace = *mock_bpftrace;
  bpftrace.procmon_ = std::make_unique<MockProcMon>(123);

  test(bpftrace, "watchpoint:func1+arg2:8:rw { 1 }");
  test(bpftrace, "w:func1+arg2:8:rw { 1 }");
  test(bpftrace, "w:func1.one_two+arg2:8:rw { 1 }");
  test_error(bpftrace, "watchpoint:func1+arg99999:8:rw { 1 }");

  bpftrace.procmon_ = nullptr;
  test_error(bpftrace, "watchpoint:func1+arg2:8:rw { 1 }");
}

TEST(attachpoint_checker, asyncwatchpoint)
{
  if (arch::Host::Machine != arch::ARM64 &&
      arch::Host::Machine != arch::X86_64) {
    GTEST_SKIP() << "Watchpoint tests are only supported on ARM64 and X86_64";
  }

  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace& bpftrace = *mock_bpftrace;
  bpftrace.procmon_ = std::make_unique<MockProcMon>(123);

  test(bpftrace, "asyncwatchpoint:func1+arg2:8:rw { 1 }");
  test(bpftrace, "aw:func1+arg2:8:rw { 1 }");
  test(bpftrace, "aw:func1.one_two+arg2:8:rw { 1 }");
  test_error(bpftrace, "asyncwatchpoint:func1+arg99999:8:rw { 1 }");

  // asyncwatchpoint's may not use absolute addresses
  test_error(bpftrace, "asyncwatchpoint:0x1234:8:rw { 1 }");

  bpftrace.procmon_ = nullptr;
  test_error(bpftrace, "watchpoint:func1+arg2:8:rw { 1 }");
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
  test("hardware:*:100000000 { 1 }", true /*listing*/);
}

TEST(attachpoint_checker, software)
{
  test("software:cpu-clock:100000000 { 1 }");
  test_error("software:tomato:100000000 { 1 }");

  // Wildcard
  test_error("software:*:100000000 { 1 }");
  test("software:*:100000000 { 1 }", true /*listing*/);
}

} // namespace attachpoint_checker

} // namespace bpftrace::test
