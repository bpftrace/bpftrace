#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_nsecs_monotonic)
{
  test("k:f { @x = nsecs(monotonic); }", NAME);
}

} // namespace bpftrace::test::codegen
