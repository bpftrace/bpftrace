#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, pred_binop)
{
  test("kprobe:f / pid == 1234 / { @x = 1 }",

       NAME);
}

} // namespace bpftrace::test::codegen
