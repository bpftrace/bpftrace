#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_zero)
{
  test("begin { @x = 1; } kprobe:f { zero(@x); }",

       NAME);
}

} // namespace bpftrace::test::codegen
