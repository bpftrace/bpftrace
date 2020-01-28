#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_delete)
{
  test("kprobe:f { @x = 1; delete(@x) }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
