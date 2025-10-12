#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_signal_target_default)
{
  test("k:f { signal(8); }", NAME, false);
}

TEST(codegen, call_signal_target_pid)
{
  // Defaults to `current_pid` if the second argument is omitted.
  test("k:f { signal(8, current_pid); }", "call_signal_target_default", false);
}

TEST(codegen, call_signal_target_tid)
{
  test("k:f { signal(8, current_tid); }", NAME, false);
}

} // namespace bpftrace::test::codegen
