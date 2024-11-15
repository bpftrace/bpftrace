#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, auto_print_variables)
{
  test("kprobe:f { $x = 0; $x }", NAME);
}

TEST(codegen, auto_print_builtins)
{
  test("kprobe:f { probe }", NAME);
}

TEST(codegen, auto_print_maps)
{
  test("kprobe:f { @x = 0; @x }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
