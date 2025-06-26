#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, builtin_sarg)
{
  test("kprobe:f { @x = sarg0; @y = sarg2 }",

       NAME);
}

} // namespace bpftrace::test::codegen
