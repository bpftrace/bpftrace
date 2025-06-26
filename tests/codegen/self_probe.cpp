#include "../mocks.h"
#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, self_probe)
{
  test("self:signal:SIGUSR1 { @x = probe }", NAME);
}

} // namespace bpftrace::test::codegen
