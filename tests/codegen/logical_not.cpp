#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, logical_not)
{
  test("BEGIN { @x = !10; @y = !0; }", NAME);
}

} // namespace bpftrace::test::codegen
