#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_percpu_kaddr)
{
  test("BEGIN { percpu_kaddr(\"process_counts\", 0); }", NAME);
}

TEST(codegen, call_percpu_kaddr_this_cpu)
{
  test("BEGIN { percpu_kaddr(\"process_counts\"); }", NAME);
}

} // namespace bpftrace::test::codegen
