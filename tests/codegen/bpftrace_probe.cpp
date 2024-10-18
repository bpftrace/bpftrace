#include "../mocks.h"
#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, bpftrace_probe)
{
  test("bpftrace:signal:SIGUSR1 { @x = probe }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
