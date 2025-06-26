#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, binop_int_promotion)
{
  test("kretprobe:f { $x = (uint32)5; $x += (uint16)1 }", NAME);
}

} // namespace bpftrace::test::codegen
