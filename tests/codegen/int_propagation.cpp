#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, int_propagation)
{
  test("kprobe:f { @x = 1234; @y = @x }",

       NAME);
}

} // namespace bpftrace::test::codegen
