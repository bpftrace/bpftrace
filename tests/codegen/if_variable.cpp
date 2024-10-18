#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, if_variable)
{
  test("kprobe:f { let $x; if (1) { $x = 10 } $y = $x; }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
