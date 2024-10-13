#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, binop_int_promotion)
{
  test("kretprobe:f { $x = (uint32)5; $x += (uint16)1 }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
