#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, kfunc_recursion_check)
{
  MockBPFtrace bpftrace;
  bpftrace.need_recursion_check_ = true;
  bpftrace.feature_ = std::make_unique<MockBPFfeature>(true);

  test(bpftrace,
       "kfunc:queued_spin_lock_slowpath { print((2)); }"
       "tracepoint:exceptions:page_fault_user { print((1)); }",
       NAME);
}

TEST(codegen, kfunc_recursion_check_with_predicate)
{
  MockBPFtrace bpftrace;
  bpftrace.need_recursion_check_ = true;
  bpftrace.feature_ = std::make_unique<MockBPFfeature>(true);

  test(bpftrace,
       "kfunc:queued_spin_lock_slowpath / pid == 1234 / { print((2)); }",
       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
