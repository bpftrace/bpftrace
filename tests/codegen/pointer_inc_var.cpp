#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, pointer_inc_var)
{
  test("kprobe:f { $v = (int16*)1000; $v++ }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
