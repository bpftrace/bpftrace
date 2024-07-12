#include "../mocks.h"
#include "common.h"

using ::testing::_;
using ::testing::Return;

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, args_multiple_tracepoints)
{
  test("tracepoint:sched:sched_one,tracepoint:sched:sched_two { "
       "@[args.common_field] = 1; }",
       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
