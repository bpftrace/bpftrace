#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_str_2_lit)
{
  test("kprobe:f { @x = str(arg0, 6) }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
