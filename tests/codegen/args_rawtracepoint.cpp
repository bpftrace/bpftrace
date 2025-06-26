#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, args_rawtracepoint)
{
  test("rawtracepoint:sched_switch { @[args.preempt] = 1; }",

       NAME);
}

} // namespace bpftrace::test::codegen
