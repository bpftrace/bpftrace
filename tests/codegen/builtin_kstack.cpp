#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_kstack)
{
  test("kprobe:f { @x = kstack }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
