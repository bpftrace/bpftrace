#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_override_literal)
{
  test("kprobe:f { override(-1); }", NAME, false);
}

} // namespace bpftrace::test::codegen
