#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, bitshift_left)
{
  test("kprobe:f { @x = 1 << 10; }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
