#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_cgroup_path)
{
  test("kprobe:f { print(cgroup_path(cgroup)); }", NAME);
}

} // namespace bpftrace::test::codegen
