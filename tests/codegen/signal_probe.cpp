#include "../mocks.h"
#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, signal_probe)
{
  test("signal:sigusr1 { @x = probe }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
