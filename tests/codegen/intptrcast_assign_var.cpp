#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, intptrcast_assign_var)
{
  test("kretprobe:f { @=*(int8*)(reg(\"bp\")-1) }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
