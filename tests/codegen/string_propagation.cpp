#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, string_propagation)
{
  test("kprobe:f { @x = \"asdf\"; @y = @x }", NAME);
}

} // namespace bpftrace::test::codegen
