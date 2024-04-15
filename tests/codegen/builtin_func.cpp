#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_func_kprobe)
{
  test("kprobe:f { @x = func }", NAME);
}

TEST(codegen, builtin_func_kretprobe)
{
  test("kretprobe:f { @x = func }", NAME);
}

TEST(codegen, builtin_func_uprobe)
{
  test("uprobe:/bin/sh:f { @x = func }", NAME);
}

TEST(codegen, builtin_func_uretprobe)
{
  test("uretprobe:/bin/sh:f { @x = func }", NAME);
}

TEST(codegen, builtin_func_kfunc)
{
  test("kfunc:f { @x = func }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
