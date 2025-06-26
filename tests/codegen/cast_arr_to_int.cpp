#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, cast_arr_to_int)
{
  test("kprobe:f { @=(uint32)pton(\"127.0.0.1\"); }", NAME);
}

} // namespace bpftrace::test::codegen
