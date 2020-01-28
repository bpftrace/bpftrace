#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_cpu)
{
  test("kprobe:f { @x = cpu }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
