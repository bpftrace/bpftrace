#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, ternary_nested)
{
  // This test ensures that when generating PHI nodes for nested blocks, the
  // incoming blocks are correctly specified.
  test("kprobe:f { let $x=1; let $y=1; let $z=1;  print(if ($x) { if ($y) { if "
       "($z) { $x } else { $y } } else { $z } } else { $y }); }",
       NAME);
}

} // namespace bpftrace::test::codegen
