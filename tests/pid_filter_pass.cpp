#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "ast/passes/pid_filter_pass.h"
#include "ast/passes/printer.h"
#include "clang_parser.h"
#include "driver.h"
#include "mocks.h"

namespace bpftrace::test::pid_filter_pass {

using ::testing::_;
using ::testing::HasSubstr;

void test(std::string_view input, bool has_pid, bool has_filter)
{
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace& bpftrace = *mock_bpftrace;
  if (has_pid) {
    bpftrace.procmon_ = std::make_unique<MockProcMon>(1);
  }

  Driver driver(bpftrace);
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  ASSERT_EQ(driver.parse_str(input), 0);

  ClangParser clang;
  ASSERT_TRUE(clang.parse(driver.ctx.root, bpftrace));

  ASSERT_EQ(driver.parse_str(input), 0);
  ast::PidFilterPass pid_filter(driver.ctx, bpftrace);
  pid_filter.analyse();

  std::string_view expected_ast = R"(
  if
   !=
    builtin: pid
    int: 1
   then
    return
)";

  std::ostringstream out;
  ast::Printer printer(driver.ctx, out);
  printer.print();

  if (has_filter) {
    EXPECT_THAT(out.str(), HasSubstr(expected_ast));
  } else {
    EXPECT_THAT(out.str(), Not(HasSubstr(expected_ast)));
  }
}

TEST(pid_filter_pass, add_filter)
{
  std::vector<std::string> filter_probes = {
    "kprobe:f",
    "kretprobe:f",
    "fentry:f",
    "fexit:f",
    "tracepoint:category:event",
    "rawtracepoint:event",
  };

  for (auto& probe : filter_probes) {
    test(probe + " { 1 }", true, true);
  }
}

TEST(pid_filter_pass, no_add_filter)
{
  // Sanity check: no pid, no filter
  test("kprobe:f { 1 }", false, false);
  test("profile:hz:99 { 1 }", false, false);

  std::vector<std::string> no_filter_probes = {
    "BEGIN",
    "END",
    "uprobe:/bin/sh:f",
    "uretprobe:/bin/sh:f",
    "usdt:sh:probe",
    "watchpoint:0x0:8:rw",
    "asyncwatchpoint:func1+arg2:8:rw",
    "profile:ms:1",
    "interval:s:1",
    "software:faults:1000",
    "hardware:cache-references:1000000",
  };

  for (auto& probe : no_filter_probes) {
    test(probe + " { 1 }", true, false);
  }
}

} // namespace bpftrace::test::pid_filter_pass
