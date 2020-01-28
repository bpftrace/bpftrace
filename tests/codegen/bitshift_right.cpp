#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, bitshift_right)
{
  test("kprobe:f { @x = 1024 >> 9; }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
