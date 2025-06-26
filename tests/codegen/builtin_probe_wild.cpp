#include "../mocks.h"
#include "common.h"

namespace bpftrace::test::codegen {

using ::testing::Return;

TEST(codegen, builtin_probe_wild)
{
  test("tracepoint:sched:sched_on* { @x = probe }", NAME);
}

} // namespace bpftrace::test::codegen
