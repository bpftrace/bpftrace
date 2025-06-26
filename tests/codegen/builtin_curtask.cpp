#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, builtin_curtask)
{
  test("kprobe:f { @x = curtask }",

       NAME);
}

} // namespace bpftrace::test::codegen
