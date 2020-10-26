#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

#ifdef ARCH_X86_64
TEST(codegen, call_reg) // Identical to builtin_func apart from variable names
{
  test("kprobe:f { @x = reg(\"ip\") }",

       NAME);
}
#endif

} // namespace codegen
} // namespace test
} // namespace bpftrace
