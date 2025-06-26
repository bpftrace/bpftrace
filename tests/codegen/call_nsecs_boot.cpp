#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_nsecs_boot)
{
  test("k:f { @x = nsecs(boot); }", NAME);
}

} // namespace bpftrace::test::codegen
