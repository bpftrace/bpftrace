#include "attached_probe.h"
#include "mocks.h"
#include "llvm/Support/Error.h"
#include "gtest/gtest.h"

namespace bpftrace {

Result<uint64_t> resolve_offset_uprobe(Probe &probe, bool safe_mode);

namespace test {

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

TEST(attached_probe, resolve_offset_uprobe_unresolvable_address_hints_unsafe)
{
  Probe probe;
  probe.type = ProbeType::uprobe;
  probe.path = "/nonexistent-binary-for-bpftrace-test";
  probe.attach_point = "";
  probe.address = 0x1000;
  probe.name = "uprobe:" + probe.path + ":0x1000";

  auto result = resolve_offset_uprobe(probe, /*safe_mode=*/true);
  ASSERT_TRUE(!result);
  auto msg = llvm::toString(result.takeError());
  EXPECT_NE(msg.find("--unsafe"), std::string::npos) << msg;
}

} // namespace test
} // namespace bpftrace
