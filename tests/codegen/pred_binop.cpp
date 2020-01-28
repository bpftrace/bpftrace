#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, pred_binop)
{
  test("kprobe:f / pid == 1234 / { @x = 1 }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
