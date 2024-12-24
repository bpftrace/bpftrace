#include "../mocks.h"
#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_probe)
{
  test("tracepoint:sched:sched_one { @x = probe }", NAME);
}

TEST(codegen, builtin_probe_comparison)
{
  test(
      R"(tracepoint:sched:sched_one { if (probe == "tracepoint:sched:sched_one") {} })",
      NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
