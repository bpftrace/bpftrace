#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_nsecs_tai)
{
  test("k:f { @x = nsecs(tai); }", NAME);
}

} // namespace bpftrace::test::codegen
