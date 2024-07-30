#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_has_key)
{
  test("kprobe:f { @x[1] = 1; has_key(@x, 1) }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
