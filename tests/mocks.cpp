#include "mocks.h"
#include "tracefs/tracefs.h"
#include "util/elf_parser.h"
#include "gmock/gmock-nice-strict.h"

namespace bpftrace::test {

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrictMock;

void setup_mock_bpftrace(MockBPFtrace &bpftrace)
{
  bpftrace.delta_taitime_ = timespec{};
  // Fill in a tracepoint struct definition so that we don't need to mock the
  // tracepoint format files.
  bpftrace.structs.Add("struct tracepoint:sched:sched_one_args", 8);
  bpftrace.structs.Lookup("struct tracepoint:sched:sched_one_args")
      .lock()
      ->AddField("common_field", CreateUInt64(), 8);
}

std::unique_ptr<MockBPFtrace> get_mock_bpftrace()
{
  auto bpftrace = std::make_unique<NiceMock<MockBPFtrace>>();
  setup_mock_bpftrace(*bpftrace);

  bpftrace->feature_ = std::make_unique<MockBPFfeature>(*bpftrace->btf_, true);

  return bpftrace;
}

std::unique_ptr<MockBPFtrace> get_strict_mock_bpftrace()
{
  auto bpftrace = std::make_unique<StrictMock<MockBPFtrace>>();
  setup_mock_bpftrace(*bpftrace);

  bpftrace->feature_ = std::make_unique<MockBPFfeature>(*bpftrace->btf_, true);

  return bpftrace;
}

} // namespace bpftrace::test
