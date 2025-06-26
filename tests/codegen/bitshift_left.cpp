#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, bitshift_left)
{
  test("kprobe:f { @x = 1 << 10; }",

       NAME);
}

} // namespace bpftrace::test::codegen
