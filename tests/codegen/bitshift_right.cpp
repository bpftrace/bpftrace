#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, bitshift_right)
{
  test("kprobe:f { @x = 1024 >> 9; }",

       NAME);
}

} // namespace bpftrace::test::codegen
