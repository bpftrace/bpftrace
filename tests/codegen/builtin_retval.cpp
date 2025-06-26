#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, builtin_retval)
{
  test("kretprobe:f { @x = retval }",

       NAME);
}

} // namespace bpftrace::test::codegen
