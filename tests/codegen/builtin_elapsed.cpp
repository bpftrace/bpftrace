#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, builtin_elapsed)
{
  test("i:s:1 { @ = elapsed; }",

       NAME);
}

} // namespace bpftrace::test::codegen
