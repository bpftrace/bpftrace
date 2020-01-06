#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, basic_while_loop)
{
  test("i:s:1 { $a = 1; while ($a <= 150) { @=$a++; }}", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
