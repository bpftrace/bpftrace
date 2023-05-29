#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, subprog_arguments)
{
  test("fn add($a : int64, $b : int64): int64 { return $a + $b; }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
