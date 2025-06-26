#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_macaddr)
{
  test("struct mac { unsigned char addr[6] } kprobe:f { @x = macaddr(((struct "
       "mac*)0)->addr); }",

       NAME);
}

} // namespace bpftrace::test::codegen
