#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, bitwise_not)
{
  test("BEGIN { @x = ~10; }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
