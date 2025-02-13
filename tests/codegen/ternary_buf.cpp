#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, ternary_buf)
{
  test("kprobe:f { $x = nsecs ? buf(\"hi\", 2) : buf(\"bye\", 3); }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
