#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_str_2_lit)
{
  test("kprobe:f { @x = str(arg0, 6) }",

       NAME);
}

} // namespace bpftrace::test::codegen
