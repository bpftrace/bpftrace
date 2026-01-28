#include "attached_probe.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test {

TEST(attached_probe, kprobe_empty_name_and_zero_address)
{
  auto mock_bpftrace = get_mock_bpftrace();

  BPFtrace &bpftrace = *mock_bpftrace;
  BpfProgram prog(nullptr);

  Probe probe;
  probe.type = ProbeType::kprobe;
  probe.attach_point = "";
  probe.address = 0;

  auto result = AttachedProbe::make(probe, prog, 0, bpftrace.safe_mode_);
  EXPECT_TRUE(!result);
}

} // namespace bpftrace::test
