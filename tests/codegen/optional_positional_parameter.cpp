#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, optional_positional_parameter)
{
  test("begin { @x = $1; @y = str($2) }", NAME);
}

} // namespace bpftrace::test::codegen
