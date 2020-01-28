#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, intcast_call)
{
  // Casting should work inside a call
  test("kretprobe:f { @=sum((int32)retval) }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
