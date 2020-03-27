#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_exit)
{
  test("kprobe:f { exit(); @=10 }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
