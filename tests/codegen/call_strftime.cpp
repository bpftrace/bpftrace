#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_strftime)
{
  test("kprobe:f { strftime(\"%M:%S\", nsecs); }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
