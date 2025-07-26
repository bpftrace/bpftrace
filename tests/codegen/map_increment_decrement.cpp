#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, map_increment_decrement)
{
  test("begin { @x = 10; @x++; ++@x; @x--; --@x; }",

       NAME);
}

} // namespace bpftrace::test::codegen
