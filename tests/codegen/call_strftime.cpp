#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_strftime)
{
  test("kprobe:f { printf(\"%s\", strftime(\"%M:%S\", nsecs)); }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
