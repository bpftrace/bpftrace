#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, pointer_inc_map)
{
  test("kprobe:f { @ = (int16*)1000; @++ }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
