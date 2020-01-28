#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_rand)
{
  test("kprobe:f { @x = rand }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
