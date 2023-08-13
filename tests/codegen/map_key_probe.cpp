#include "../mocks.h"
#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, map_key_probe)
{
  test("tracepoint:sched:sched_one,tracepoint:sched:sched_two { @x[probe] = "
       "@x[probe] + 1 }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
