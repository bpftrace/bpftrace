#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, pointer_add_int)
{
  test("kprobe:f { $v = (int16*)1000; $v += 10; }", NAME);
}

} // namespace bpftrace::test::codegen
