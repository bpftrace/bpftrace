#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, logical_and)
{
  test("kprobe:f { @x = pid != 1234 && pid != 1235 }",

       NAME);
}

} // namespace bpftrace::test::codegen
