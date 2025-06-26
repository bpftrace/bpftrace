#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_ntop_char4)
{
  test("struct inet { unsigned char addr[4] } kprobe:f { @x = ntop(((struct "
       "inet*)0)->addr); }",

       NAME);
}

} // namespace bpftrace::test::codegen
