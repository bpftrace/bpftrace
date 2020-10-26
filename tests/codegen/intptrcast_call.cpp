#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

#ifdef ARCH_X86_64
TEST(codegen, intptrcast_call)
{
  // Casting should work inside a call
  test("kretprobe:f { @=sum(*(int8*)(reg(\"bp\")-1)) }", NAME);
}
#endif

} // namespace codegen
} // namespace test
} // namespace bpftrace
