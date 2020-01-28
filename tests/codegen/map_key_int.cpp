#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, map_key_int)
{
  test("kprobe:f { @x[11,22,33] = 44 }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
