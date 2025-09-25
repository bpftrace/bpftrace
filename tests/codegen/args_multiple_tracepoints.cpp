#include "../mocks.h"
#include "common.h"

using ::testing::_;
using ::testing::Return;

namespace bpftrace::test::codegen {

TEST(codegen, args_multiple_tracepoints)
{
  test("tracepoint:sched:sched_one,tracepoint:sched:sched_one_twin { "
       "@[args.common_field] = 1; }",
       NAME);
}

} // namespace bpftrace::test::codegen
