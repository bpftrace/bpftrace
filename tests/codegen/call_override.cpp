#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_override)
{
  test("kprobe:f { override(arg0); }", NAME, false);
}

} // namespace bpftrace::test::codegen
