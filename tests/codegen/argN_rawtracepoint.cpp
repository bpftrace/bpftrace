#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, argN_rawtracepoint)
{
  test("rawtracepoint:sched_switch { @[arg0] = 1; }",

       NAME);
}

} // namespace bpftrace::test::codegen
