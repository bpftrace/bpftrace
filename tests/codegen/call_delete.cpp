#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_delete)
{
  test("kprobe:f { @x[1] = 1; delete(@x, 1) }",

       NAME);
}

TEST(codegen, call_delete_deprecated)
{
  test("kprobe:f { @x[1] = 1; delete(@x[1]) }",

       NAME);
}

} // namespace bpftrace::test::codegen
