#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_nsecs)
{
  test("kprobe:f { @x = nsecs }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
