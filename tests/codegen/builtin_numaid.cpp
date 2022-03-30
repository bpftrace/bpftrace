#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_numaid)
{
  test("kprobe:f { @x = numaid }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
