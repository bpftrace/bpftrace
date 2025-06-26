#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, builtin_comm)
{
  test("kprobe:f { @x = comm }", NAME);
}

} // namespace bpftrace::test::codegen
