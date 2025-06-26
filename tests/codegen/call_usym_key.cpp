#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_usym_key)
{
  test("kprobe:f { @x[usym(0)] = 1; }",

       NAME);
}

} // namespace bpftrace::test::codegen
