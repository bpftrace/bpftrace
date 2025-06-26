#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, builtin_numaid)
{
  test("kprobe:f { @x = numaid }",

       NAME);
}

} // namespace bpftrace::test::codegen
