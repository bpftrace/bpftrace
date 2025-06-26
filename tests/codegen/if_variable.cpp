#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, if_variable)
{
  test("kprobe:f { let $x; if (1) { $x = 10 } $y = $x; }",

       NAME);
}

} // namespace bpftrace::test::codegen
