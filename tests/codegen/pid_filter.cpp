#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, pid_filter)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->procmon_ = std::make_unique<MockProcMon>(1);

  test(*bpftrace, "kprobe:f { $x = 1 }", NAME);
}

} // namespace bpftrace::test::codegen
