#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_pid_tid)
{
  test("kprobe:f { @x = pid(); @y = tid() }", NAME);
}

TEST(codegen, call_pid_tid_in_child_ns)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->mock_in_init_pid_ns = false;
  bpftrace->helper_check_level_ = 0;

  test(*bpftrace, "kprobe:f { @x = pid(); @y = tid() }", NAME);
}

TEST(codegen, call_pid_tid_curr_ns)
{
  test("kprobe:f { @x = pid(curr_ns); @y = tid(curr_ns) }", NAME);
}

TEST(codegen, call_pid_tid_curr_ns_in_child_ns)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->mock_in_init_pid_ns = false;
  bpftrace->helper_check_level_ = 0;

  test(*bpftrace, "kprobe:f { @x = pid(curr_ns); @y = tid(curr_ns) }", NAME);
}

TEST(codegen, call_pid_tid_init)
{
  test("kprobe:f { @x = pid(init); @y = tid(init) }", NAME);
}

TEST(codegen, call_pid_tid_init_ns_in_child_ns)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->mock_in_init_pid_ns = false;
  bpftrace->helper_check_level_ = 0;

  test(*bpftrace, "kprobe:f { @x = pid(init); @y = tid(init) }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
