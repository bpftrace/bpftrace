#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_pid_tid)
{
  test("kprobe:f { @x = pid; @y = tid }", NAME);
}

TEST(codegen, builtin_pid_tid_namespace)
{
  MockBPFtrace bpftrace;
  bpftrace.feature_ = std::make_unique<MockBPFfeature>(true);
  bpftrace.mock_in_init_pid_ns = false;
  bpftrace.helper_check_level_ = 0;

  test(bpftrace, "kprobe:f { @x = pid; @y = tid }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
