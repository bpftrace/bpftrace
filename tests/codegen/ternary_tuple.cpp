#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, ternary_tuple)
{
  test("kprobe:f { $x = nsecs ? (\"hi\", 1) : (\"extralongstring\", 2) }",
       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
