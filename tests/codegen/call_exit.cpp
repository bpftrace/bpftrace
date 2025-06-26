#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_exit)
{
  test("kprobe:f { exit(); @=10 }", NAME);
}

TEST(codegen, call_exit_with_error_code)
{
  test("kprobe:f { exit(1); }", NAME);
}

} // namespace bpftrace::test::codegen
