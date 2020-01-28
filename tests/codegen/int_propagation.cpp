#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, int_propagation)
{
  test("kprobe:f { @x = 1234; @y = @x }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
