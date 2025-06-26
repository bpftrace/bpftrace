#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, pointer_inc_var)
{
  test("kprobe:f { $v = (int16*)1000; $v++ }", NAME);
}

} // namespace bpftrace::test::codegen
