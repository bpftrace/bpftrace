#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, map_assign_int)
{
  test("kprobe:f { @x = 1; }",

       NAME);
}

} // namespace bpftrace::test::codegen
