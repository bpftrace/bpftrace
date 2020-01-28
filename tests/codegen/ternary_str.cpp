#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, ternary_str)
{
  test("kprobe:f { @x = pid < 10000 ? \"lo\" : \"hi\"; }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
