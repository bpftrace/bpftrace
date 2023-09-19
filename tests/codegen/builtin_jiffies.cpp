#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_jiffies)
{
  test("kprobe:f { @x = jiffies }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
