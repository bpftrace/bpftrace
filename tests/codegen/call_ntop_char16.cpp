#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_ntop_char16)
{
  test("struct inet { unsigned char addr[16] } kprobe:f { @x = ntop(((struct "
       "inet*)0)->addr); }",

       NAME);
}

} // namespace bpftrace::test::codegen
