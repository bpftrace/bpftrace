#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, builtin_ncpus)
{
  test("begin { @x = ncpus; exit(); }", NAME);
}

} // namespace bpftrace::test::codegen
