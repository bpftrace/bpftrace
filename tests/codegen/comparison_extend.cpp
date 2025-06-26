#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, comparison_extend)
{
  // Make sure i1 is zero extended
  test("kprobe:f { @ = 1 < arg0 }",

       NAME);
}

} // namespace bpftrace::test::codegen
