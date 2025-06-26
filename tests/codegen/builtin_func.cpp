#include "common.h"

namespace bpftrace::test::codegen {

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

TEST(codegen, builtin_func_fentry)
{
  test("fentry:f { @x = func }", NAME);
}

} // namespace bpftrace::test::codegen
