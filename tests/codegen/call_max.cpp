#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_max)
{
  test("kprobe:f { @x = max(pid) }",

       NAME);
}

} // namespace bpftrace::test::codegen
