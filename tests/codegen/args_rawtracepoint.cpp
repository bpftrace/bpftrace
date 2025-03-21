#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, args_rawtracepoint)
{
  test("rawtracepoint:sched_switch { @[args.preempt] = 1; }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
