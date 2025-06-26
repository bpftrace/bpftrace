#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, block_expression)
{
  test("kprobe:f { $a = { let $b = 4; $b } }", NAME);
}

} // namespace bpftrace::test::codegen
