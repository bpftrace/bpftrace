#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, builtin_kstack)
{
  test("kprobe:f { @x = kstack }",

       NAME);
}

} // namespace bpftrace::test::codegen
