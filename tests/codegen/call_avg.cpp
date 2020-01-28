#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_avg)
{
  test("kprobe:f { @x = avg(pid) }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
