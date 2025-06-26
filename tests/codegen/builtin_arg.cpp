#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, builtin_arg)
{
  test("kprobe:f { @x = arg0; @y = arg2 }",

       NAME);
}

} // namespace bpftrace::test::codegen
