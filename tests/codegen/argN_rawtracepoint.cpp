#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, argN_rawtracepoint)
{
  test("rawtracepoint:sched_switch { @[arg0] = 1; }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
