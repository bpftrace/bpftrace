#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_lhist)
{
  test("kprobe:f { @x = lhist(pid, 0, 100, 1) }",

       NAME);
}

} // namespace bpftrace::test::codegen
