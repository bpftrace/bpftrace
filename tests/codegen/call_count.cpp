#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_count)
{
  test("kprobe:f { @x = count() }",

       NAME);
}

} // namespace bpftrace::test::codegen
