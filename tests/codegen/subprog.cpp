#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, subprog_arguments)
{
  test("fn add($a : int64, $b : int64): int64 { return $a + $b; }", NAME);
}

} // namespace bpftrace::test::codegen
