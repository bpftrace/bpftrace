#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, block_expression)
{
  test("kprobe:f { $a = { let $b = 4; $b } }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
