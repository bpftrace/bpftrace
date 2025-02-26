#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, fentry_recursion_check)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->btf_ = nullptr;
  bpftrace->set_func_modules({ "vmlinux" });

  test(*bpftrace,
       "fentry:queued_spin_lock_slowpath { }"
       "tracepoint:exceptions:page_fault_user { }",
       NAME);
}

TEST(codegen, fentry_recursion_check_with_predicate)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->btf_ = nullptr;
  bpftrace->set_func_modules({ "vmlinux" });

  test(*bpftrace, "fentry:queued_spin_lock_slowpath / pid == 1234 / { }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
