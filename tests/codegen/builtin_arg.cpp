#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_arg)
{
  test("kprobe:f { @x = arg0; @y = arg2 }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
