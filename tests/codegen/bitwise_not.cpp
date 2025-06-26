#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, bitwise_not)
{
  test("BEGIN { @x = ~10; }", NAME);
}

} // namespace bpftrace::test::codegen
