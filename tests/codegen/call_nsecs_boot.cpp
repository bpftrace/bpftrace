#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_nsecs_boot)
{
  test("k:f { @x = nsecs(boot); }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
