#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_retval)
{
  test("kretprobe:f { @x = retval }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
