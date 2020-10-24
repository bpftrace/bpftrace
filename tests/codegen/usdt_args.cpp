#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, usdt1)
{
  test("usdt:./testprogs/usdt_sized_args:test:probe2 {  $x = arg0; }", NAME);
}

TEST(codegen, usdt2)
{
  test("usdt:./testprogs/usdt_semaphore_test:tracetest:testprobe { $x = "
       "str(arg1); }",
       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
