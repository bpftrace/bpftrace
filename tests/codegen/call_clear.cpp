#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_clear)
{
  test("BEGIN { @x = 1; } kprobe:f { clear(@x); }",

       NAME);
}

} // namespace bpftrace::test::codegen
