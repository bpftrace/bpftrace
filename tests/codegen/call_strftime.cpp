#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_strftime)
{
  test("kprobe:f { strftime(\"%M:%S\", nsecs); }", NAME);
}

} // namespace bpftrace::test::codegen
