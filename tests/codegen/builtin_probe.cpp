#include "../mocks.h"
#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, builtin_probe)
{
  test("tracepoint:sched:sched_one { @x = probe }", NAME);
}

} // namespace bpftrace::test::codegen
