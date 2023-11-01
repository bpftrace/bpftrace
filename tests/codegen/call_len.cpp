#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_len)
{
  test("BEGIN { @x[1] = 1; } kprobe:f { $s = len(@x); }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
