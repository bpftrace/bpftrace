#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_sum)
{
  test("kprobe:f { @x = sum(pid) }",

       NAME);
}

} // namespace bpftrace::test::codegen
