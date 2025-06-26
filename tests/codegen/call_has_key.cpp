#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_has_key)
{
  test("kprobe:f { @x[1] = 1; has_key(@x, 1) }", NAME);
}

} // namespace bpftrace::test::codegen
