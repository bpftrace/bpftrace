#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

#ifdef __x86_64__
TEST(codegen, call_reg) // Identical to builtin_func apart from variable names
{
  test("kprobe:f { @x = reg(\"ip\") }",

       NAME);
}
#endif

} // namespace codegen
} // namespace test
} // namespace bpftrace
