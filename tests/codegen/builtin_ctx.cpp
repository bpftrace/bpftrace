#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_ctx)
{
  test("kprobe:f { @x = (uint64)ctx }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
