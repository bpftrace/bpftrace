#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_ustack)
{
  test("kprobe:f { @x = ustack }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
