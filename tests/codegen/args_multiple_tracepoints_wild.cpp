#include "../mocks.h"
#include "common.h"

using ::testing::_;
using ::testing::Return;

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, args_multiple_tracepoints_wild)
{
  test("tracepoint:sched:sched_* { @[args.common_field] = count(); }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
