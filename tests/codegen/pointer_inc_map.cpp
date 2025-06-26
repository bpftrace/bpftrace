#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, pointer_inc_map)
{
  test("kprobe:f { @ = (int16*)1000; @++ }", NAME);
}

} // namespace bpftrace::test::codegen
