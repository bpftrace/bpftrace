#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, variable)
{
  test("kprobe:f { $var = comm; @x = $var; @y = $var }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
