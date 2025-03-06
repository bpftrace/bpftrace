#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, block_expression_complex)
{
  test("kprobe:f { @x = { let $p = pid; avg(pid) } }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
