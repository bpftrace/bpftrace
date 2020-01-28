#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, unroll)
{
  test("BEGIN { @i = 0; unroll(5) { @i += 1 } }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
