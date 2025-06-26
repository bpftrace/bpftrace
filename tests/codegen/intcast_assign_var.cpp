#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, intcast_retval)
{
  // Make sure the result is truncated to 32 bit and sign extended to 64
  test("kretprobe:f { @=(int32)retval }", NAME);
}

} // namespace bpftrace::test::codegen
