#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, logical_not)
{
  test("BEGIN { @x = !10; @y = !0; }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
