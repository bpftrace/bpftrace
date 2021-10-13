#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_cgroup_path)
{
  test("kprobe:f { print(cgroup_path(cgroup)); }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
