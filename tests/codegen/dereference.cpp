#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, dereference)
{
  test("kprobe:f { @x = *kptr(1234) }",

       NAME);
}

} // namespace bpftrace::test::codegen
