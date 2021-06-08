#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, runtime_error_check)
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
