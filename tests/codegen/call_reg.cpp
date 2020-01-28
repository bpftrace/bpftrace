#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_reg) // Identical to builtin_func apart from variable names
{
  test("kprobe:f { @x = reg(\"ip\") }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
