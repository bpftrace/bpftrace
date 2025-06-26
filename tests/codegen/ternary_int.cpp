#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, ternary_int)
{
  test("kprobe:f { @x = pid < 10000 ? 1 : 2; }", NAME);
}

} // namespace bpftrace::test::codegen
