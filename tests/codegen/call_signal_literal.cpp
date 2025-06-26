#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_signal_literal)
{
  test("k:f { signal(8); }", NAME, false);
}

} // namespace bpftrace::test::codegen
