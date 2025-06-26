#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, ternary_none)
{
  test("kprobe:f { pid < 10000 ? printf(\"hello\") : exit(); }", NAME);
}

} // namespace bpftrace::test::codegen
