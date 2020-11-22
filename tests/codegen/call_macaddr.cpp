#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_macaddr)
{
  test("struct mac { unsigned char addr[6] } kprobe:f { @x = macaddr(((struct "
       "mac*)0)->addr); }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
