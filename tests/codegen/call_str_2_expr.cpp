#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_str_2_expr)
{
  test("kprobe:f { @x = str(arg0, arg1) }",

       NAME);
}

} // namespace bpftrace::test::codegen
