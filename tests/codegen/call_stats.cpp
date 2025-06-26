#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_stats)
{
  test("kprobe:f { @x = stats(pid) }",

       NAME);
}

} // namespace bpftrace::test::codegen
