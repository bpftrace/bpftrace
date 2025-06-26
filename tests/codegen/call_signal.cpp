#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_signal)
{
  test("k:f { signal(arg0); }", NAME, false);
}

} // namespace bpftrace::test::codegen
