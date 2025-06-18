#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_tseries)
{
  test("kprobe:f { @a = 4; @x = tseries(@a, \"1s\", 20) }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
