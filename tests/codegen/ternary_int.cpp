#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, ternary_int)
{
  test("kprobe:f { @x = pid < 10000 ? 1 : 2; }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
