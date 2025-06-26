#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, builtin_jiffies)
{
  test("kprobe:f { @x = jiffies }",

       NAME);
}

} // namespace bpftrace::test::codegen
