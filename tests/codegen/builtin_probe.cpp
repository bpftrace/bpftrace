#include "../mocks.h"
#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_probe)
{
  test("tracepoint:sched:sched_one { @x = probe }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
