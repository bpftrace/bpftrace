#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, pid_filter)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->procmon_ = std::make_unique<MockProcMon>(1);

  test(*bpftrace, "kprobe:f { $x = 1 }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
