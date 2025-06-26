#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_avg)
{
  test("kprobe:f { @x = avg(pid) }", NAME);
}

} // namespace bpftrace::test::codegen
