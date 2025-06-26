#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, map_key_int)
{
  test("kprobe:f { @x[11,22,33] = 44 }",

       NAME);
}

} // namespace bpftrace::test::codegen
