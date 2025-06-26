#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, license)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->config_->license = "Dual BSD/GPL";

  test(*bpftrace, "kprobe:f { @x = 1; }", NAME);
}

} // namespace bpftrace::test::codegen
