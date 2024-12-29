#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, count_cast)
{
  test("kprobe:f { @x = count(); $res = @x; }", NAME);
}

TEST(codegen, sum_cast)
{
  test("kprobe:f { @x = sum(2); $res = @x; }", NAME);
}

TEST(codegen, min_cast)
{
  test("kprobe:f { @x = min(2); $res = @x; }", NAME);
}

TEST(codegen, max_cast)
{
  test("kprobe:f { @x = max(2); $res = @x; }", NAME);
}

TEST(codegen, avg_cast)
{
  test("kprobe:f { @x = avg(2); $res = @x; }", NAME);
}

TEST(codegen, count_cast_loop)
{
  test("kprobe:f { @x[1] = count(); for ($kv : @x) { $res = $kv.1; } }", NAME);
}

TEST(codegen, sum_cast_loop)
{
  test("kprobe:f { @x[1] = sum(2); for ($kv : @x) { $res = $kv.1; } }", NAME);
}

TEST(codegen, min_cast_loop)
{
  test("kprobe:f { @x[1] = min(2); for ($kv : @x) { $res = $kv.1; } }", NAME);
}

TEST(codegen, max_cast_loop)
{
  test("kprobe:f { @x[1] = max(2); for ($kv : @x) { $res = $kv.1; } }", NAME);
}

TEST(codegen, avg_cast_loop)
{
  test("kprobe:f { @x[1] = avg(2); for ($kv : @x) { $res = $kv.1; } }", NAME);
}

TEST(codegen, count_no_cast_for_print)
{
  test("BEGIN { @ = count(); print(@) }", NAME);
}

TEST(codegen, count_cast_loop_multi_key)
{
  test("kprobe:f { @x[1, 2] = count(); for ($kv : @x) { $res = $kv.1; } }",
       NAME);
}

TEST(codegen, count_cast_loop_stack_key)
{
  test("kprobe:f { @x[kstack(raw)] = count(); for ($kv : @x) { $res = $kv.1; } "
       "}",
       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
