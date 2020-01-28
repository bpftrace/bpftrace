#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_sarg)
{
  test("kprobe:f { @x = sarg0; @y = sarg2 }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
