#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, builtin_username)
{
  test("kprobe:f { @x = username; @y = gid}",

       NAME);
}

} // namespace bpftrace::test::codegen
