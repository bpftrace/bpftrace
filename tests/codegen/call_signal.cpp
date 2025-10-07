#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_signal)
{
  test("k:f { signal(8); }", NAME, false);
}

TEST(codegen, call_signal_thread)
{
  test("k:f { signal_thread(8); }", NAME, false);
}

TEST(codegen, call_signal_string_literal)
{
  test("k:f { signal(\"SIGKILL\"); }", NAME, false);
}

} // namespace bpftrace::test::codegen
