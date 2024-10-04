#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, variable_pre_inc)
{
  test("BEGIN { $x = 10; $y = ++$x; }", NAME);
}

TEST(codegen, variable_post_inc)
{
  test("BEGIN { $x = 10; $y = $x++; }", NAME);
}

TEST(codegen, variable_pre_dec)
{
  test("BEGIN { $x = 10; $y = --$x; }", NAME);
}

TEST(codegen, variable_post_dec)
{
  test("BEGIN { $x = 10; $y = $x--; }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
