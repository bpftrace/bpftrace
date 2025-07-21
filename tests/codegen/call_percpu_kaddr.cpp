#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_percpu_kaddr)
{
  test("begin { percpu_kaddr(\"process_counts\", 0); }", NAME);
}

TEST(codegen, call_percpu_kaddr_this_cpu)
{
  test("begin { percpu_kaddr(\"process_counts\"); }", NAME);
}

} // namespace bpftrace::test::codegen
