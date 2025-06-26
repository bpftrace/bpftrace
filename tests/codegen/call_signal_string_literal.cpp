#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_signal_string_literal)
{
  test("k:f { signal(\"SIGKILL\"); }", NAME, false);
}

} // namespace bpftrace::test::codegen
