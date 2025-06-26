#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, block_expression_cond)
{
  test("kprobe:f { if ({ let $a = true; $a }) { exit() } }", NAME);
}

} // namespace bpftrace::test::codegen
