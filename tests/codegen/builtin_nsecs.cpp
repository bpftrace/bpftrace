#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, builtin_nsecs)
{
  test("kprobe:f { @x = nsecs }",

       NAME);
}

} // namespace bpftrace::test::codegen
