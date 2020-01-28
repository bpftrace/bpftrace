#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_ntop_char4)
{
  test("struct inet { unsigned char addr[4] } kprobe:f { @x = ntop(((struct "
       "inet*)0)->addr); }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
