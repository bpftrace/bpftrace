#include "../mocks.h"
#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

using ::testing::Return;

TEST(codegen, builtin_probe_wild)
{
  test("tracepoint:sched:sched_on* { @x = probe }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
