#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, builtin_cpu)
{
  test("kprobe:f { @x = cpu }",

       NAME);
}

} // namespace bpftrace::test::codegen
