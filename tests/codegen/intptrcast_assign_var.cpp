#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

#ifdef ARCH_X86_64
TEST(codegen, intptrcast_assign_var)
{
  test("kretprobe:f { @=*(int8*)(reg(\"bp\")-1) }", NAME);
}
#endif

} // namespace codegen
} // namespace test
} // namespace bpftrace
