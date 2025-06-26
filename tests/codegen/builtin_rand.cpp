#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, builtin_rand)
{
  test("kprobe:f { @x = rand }",

       NAME);
}

} // namespace bpftrace::test::codegen
