#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, builtin_ncpus)
{
  test("BEGIN { @x = ncpus; exit(); }", NAME);
}

} // namespace bpftrace::test::codegen
