#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, fentry_recursion_check)
{
  MockBPFtrace bpftrace;
  bpftrace.need_recursion_check_ = true;
  bpftrace.feature_ = std::make_unique<MockBPFfeature>(true);

  test(bpftrace,
       "fentry:queued_spin_lock_slowpath { }"
       "tracepoint:exceptions:page_fault_user { }",
       NAME);
}

TEST(codegen, fentry_recursion_check_with_predicate)
{
  MockBPFtrace bpftrace;
  bpftrace.need_recursion_check_ = true;
  bpftrace.feature_ = std::make_unique<MockBPFfeature>(true);

  test(bpftrace, "fentry:queued_spin_lock_slowpath / pid == 1234 / { }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
