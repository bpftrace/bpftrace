#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, unroll_async_id)
{
  test(R"(BEGIN { @i = 0; unroll(5) { printf("hi") } })", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
