#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, string_propagation)
{
  test("kprobe:f { @x = \"asdf\"; @y = @x }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
