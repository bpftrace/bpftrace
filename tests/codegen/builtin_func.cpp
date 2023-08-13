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
  test("uprobe:/bin/sh:f { @x = func }", NAME);
}

TEST(codegen, builtin_func_kfunc)
{
  test("kfunc:f { @x = func }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
