#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, logical_and)
{
  test("kprobe:f { @x = pid != 1234 && pid != 1235 }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
