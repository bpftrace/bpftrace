#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, builtin_uid_gid)
{
  test("kprobe:f { @x = uid; @y = gid }",

       NAME);
}

} // namespace bpftrace::test::codegen
