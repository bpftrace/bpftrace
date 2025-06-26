#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, block_expression_complex)
{
  test("kprobe:f { @x = { let $p = pid; avg(pid) } }", NAME);
}

} // namespace bpftrace::test::codegen
