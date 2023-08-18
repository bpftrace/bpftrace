#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_nsecs_monotonic)
{
  test("k:f { @x = nsecs(monotonic); }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
