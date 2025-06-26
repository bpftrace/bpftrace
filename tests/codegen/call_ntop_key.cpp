#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_ntop_key)
{
  test("kprobe:f { @x[ntop(2, 0xFFFFFFFF)] = 1; }",

       NAME);
}

} // namespace bpftrace::test::codegen
