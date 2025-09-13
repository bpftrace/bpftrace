#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, fentry_recursion_check)
{
  auto bpftrace = get_mock_bpftrace();

  test(*bpftrace,
       "fentry:queued_spin_lock_slowpath { }"
       "tracepoint:exceptions:page_fault_user { }",
       NAME);
}

TEST(codegen, fentry_recursion_check_with_predicate)
{
  auto bpftrace = get_mock_bpftrace();

  test(*bpftrace, "fentry:queued_spin_lock_slowpath / pid == 1234 / { }", NAME);
}

} // namespace bpftrace::test::codegen
