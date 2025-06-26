#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, variable)
{
  test("kprobe:f { $var = comm; @x = $var; @y = $var }", NAME);
}

} // namespace bpftrace::test::codegen
