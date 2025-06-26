#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, cast_int_to_arr)
{
  test("kprobe:f { $a=(uint8[8])0; @ = $a[0]; }", NAME);
}

} // namespace bpftrace::test::codegen
