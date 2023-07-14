#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_nsecs_tai)
{
  test("k:f { @x = nsecs(tai); }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
