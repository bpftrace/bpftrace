#include "../mocks.h"
#include "common.h"

using ::testing::_;
using ::testing::Return;

namespace bpftrace::test::codegen {

TEST(codegen, args_tracepoint)
{
  test("tracepoint:sched:sched_one { @[args.common_field] = 1; }", NAME);
}

} // namespace bpftrace::test::codegen
