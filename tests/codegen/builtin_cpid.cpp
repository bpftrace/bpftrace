#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_cpid)
{
  MockBPFtrace bpftrace;
  bpftrace.child_ = std::make_unique<MockChildProc>("");
  bpftrace.feature_ = std::make_unique<MockBPFfeature>(true);

  test(bpftrace, "kprobe:f { @ = cpid }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
