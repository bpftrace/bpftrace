#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, unroll_async_id)
{
  test(R"(BEGIN { $i = 0; unroll(5) { $i += 1; } })", NAME);
}

} // namespace bpftrace::test::codegen
