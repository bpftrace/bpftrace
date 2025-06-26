#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_str)
{
  test("kprobe:f { @x = str(arg0) }",

       NAME);
}

} // namespace bpftrace::test::codegen
