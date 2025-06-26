#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, if_else_variable)
{
  test("kprobe:f { if (1) { $s = 10 } else { $s = 20 } }",

       NAME);
}

} // namespace bpftrace::test::codegen
