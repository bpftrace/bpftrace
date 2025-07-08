#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_tseries)
{
  test("kprobe:f { @a = 4; @x = tseries(@a, 1s, 20) }", NAME);
}

} // namespace bpftrace::test::codegen
