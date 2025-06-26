#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, basic_while_loop)
{
  test("i:s:1 { $a = 1; while ($a <= 150) { @=$a++; }}", NAME);
}

} // namespace bpftrace::test::codegen
