#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, variable_pre_inc)
{
  test("begin { $x = 10; $y = ++$x; }", NAME);
}

TEST(codegen, variable_post_inc)
{
  test("begin { $x = 10; $y = $x++; }", NAME);
}

TEST(codegen, variable_pre_dec)
{
  test("begin { $x = 10; $y = --$x; }", NAME);
}

TEST(codegen, variable_post_dec)
{
  test("begin { $x = 10; $y = $x--; }", NAME);
}

} // namespace bpftrace::test::codegen
