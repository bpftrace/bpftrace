#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, if_else_variable)
{
  test("kprobe:f { if (1) { $s = 10 } else { $s = 20 } }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
