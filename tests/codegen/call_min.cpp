#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_min)
{
  test("kprobe:f { @x = min(pid) }",

       NAME);
}

} // namespace bpftrace::test::codegen
