#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, runtime_error_check_lookup_percpu)
{
  auto bpftrace = get_mock_bpftrace();

  bpftrace->helper_check_level_ = 1;

  test(*bpftrace, "kprobe:f { @ = count(); $a = @; }", NAME);
}

TEST(codegen, runtime_error_check_delete)
{
  auto bpftrace = get_mock_bpftrace();

  bpftrace->helper_check_level_ = 1;

  test(*bpftrace, "kprobe:f { @x[1] = 1; delete(@x, 1) }", NAME);
}

TEST(codegen, runtime_error_check_pid_tid)
{
  auto bpftrace = get_mock_bpftrace();

  bpftrace->helper_check_level_ = 1;

  test(*bpftrace, "kprobe:f { @x = pid; @y = tid }", NAME);
}

TEST(codegen, runtime_error_check_comm)
{
  auto bpftrace = get_mock_bpftrace();

  bpftrace->helper_check_level_ = 1;

  test(*bpftrace, "kprobe:f { @x = comm; }", NAME);
}

TEST(codegen, runtime_error_check_signal)
{
  auto bpftrace = get_mock_bpftrace();

  bpftrace->helper_check_level_ = 1;
  bpftrace->safe_mode_ = false;

  test(*bpftrace, "kprobe:f { signal(8); }", NAME);
}

TEST(codegen, runtime_error_check_path)
{
  auto bpftrace = get_mock_bpftrace();

  bpftrace->helper_check_level_ = 1;

  test(*bpftrace, "fentry:filp_close { path((uint8 *)0); }", NAME);
}

TEST(codegen, runtime_error_check_printf)
{
  auto bpftrace = get_mock_bpftrace();

  bpftrace->helper_check_level_ = 1;

  test(*bpftrace, "iter:task_file { printf(\"%d\", 1); }", NAME);
}

TEST(codegen, runtime_error_check_for_map)
{
  auto bpftrace = get_mock_bpftrace();

  bpftrace->helper_check_level_ = 1;

  test(*bpftrace,
       "BEGIN { @map[16] = 32; for ($kv : @map) { @x = $kv; } }",
       NAME);
}

TEST(codegen, runtime_error_check_stack)
{
  auto bpftrace = get_mock_bpftrace();

  bpftrace->helper_check_level_ = 1;

  test(*bpftrace, "kprobe:f { @x = ustack; @y = kstack }", NAME);
}

TEST(codegen, runtime_error_check_lookup_no_warning)
{
  auto bpftrace = get_mock_bpftrace();

  bpftrace->helper_check_level_ = 1;

  test(*bpftrace, "kprobe:f { @++; }", NAME);
}

TEST(codegen, runtime_error_check_lookup)
{
  auto bpftrace = get_mock_bpftrace();

  bpftrace->helper_check_level_ = 2;

  test(*bpftrace, "kprobe:f { @++; }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
