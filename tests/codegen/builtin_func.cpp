#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_func)
{
  test("kprobe:f { @x = func }", NAME);
}

TEST(codegen, builtin_func_uprobe)
{
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace, "uprobe:/bin/sh:f { @x = func }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
