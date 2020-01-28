#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_str_2_expr)
{
  test("kprobe:f { @x = str(arg0, arg1) }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
