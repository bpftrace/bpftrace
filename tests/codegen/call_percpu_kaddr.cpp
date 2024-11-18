#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_percpu_kaddr)
{
  test("BEGIN { percpu_kaddr(\"process_counts\", 0); }", NAME);
}

TEST(codegen, call_percpu_kaddr_this_cpu)
{
  test("BEGIN { percpu_kaddr(\"process_counts\"); }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
