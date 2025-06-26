#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, builtin_ustack)
{
  test("kprobe:f { @x = ustack }",

       NAME);
}

} // namespace bpftrace::test::codegen
