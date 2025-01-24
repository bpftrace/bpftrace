#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

#ifdef __x86_64__
TEST(codegen, intptrcast_assign_var)
{
  test("kretprobe:f { @=*(int8*)(reg(\"bp\")-1) }", NAME);
}
#endif

} // namespace codegen
} // namespace test
} // namespace bpftrace
