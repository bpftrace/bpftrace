#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_comm)
{
  test("kprobe:f { @x = comm }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
