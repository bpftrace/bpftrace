#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_hist)
{
  test("kprobe:f { @x = hist(pid) }",

       NAME);
}

} // namespace bpftrace::test::codegen
