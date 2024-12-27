#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, pointer_if_condition)
{
  test("kprobe:f { $v = (int16*)1; if ($v) {} }", NAME);
}

TEST(codegen, pointer_tenary_expression)
{
  test("kprobe:f { $v = (int16*)1; $x = $v ? 1 : 0 }", NAME);
}

TEST(codegen, pointer_logical_and)
{
  test("kprobe:f { $v = (int16*)1; if ($v && 0) {} }", NAME);
}

TEST(codegen, pointer_logical_or)
{
  test("kprobe:f { $v = (int16*)1; if ($v || 0) {} }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
