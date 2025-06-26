#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, builtin_ctx)
{
  test("kprobe:f { @x = (uint64)ctx }", NAME);
}

} // namespace bpftrace::test::codegen
