#include "common.h"

namespace bpftrace::test::codegen::call_len {

TEST(codegen, call_len_ustack_kstack)
{
  test("kprobe:f { @x = len(ustack); @y = len(kstack); }", NAME);
}

} // namespace bpftrace::test::codegen::call_len
