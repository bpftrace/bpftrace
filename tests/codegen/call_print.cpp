#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_print)
{
  test("begin { @x = 1; } kprobe:f { print(@x); }",

       NAME);
}

} // namespace bpftrace::test::codegen
