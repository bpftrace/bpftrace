#include "../mocks.h"
#include "common.h"

namespace bpftrace::test::codegen {

using ::testing::Return;

TEST(codegen, builtin_func_wild)
{
  test("kprobe:sys_* { @x = func }", NAME);
}

} // namespace bpftrace::test::codegen
