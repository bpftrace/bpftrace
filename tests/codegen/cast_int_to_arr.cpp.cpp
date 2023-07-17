#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, cast_int_to_arr)
{
  test("kprobe:f { $a=(uint8[8])pid; @ = $a[0]; }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
