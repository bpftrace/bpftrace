#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, pointer_add_int)
{
  test("kprobe:f { $v = (int16*)1000; $v += 10; }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
