#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, intcast_call)
{
  // Casting should work inside a call
  test("kretprobe:f { @=sum((int32)retval) }", NAME);
}

} // namespace bpftrace::test::codegen
