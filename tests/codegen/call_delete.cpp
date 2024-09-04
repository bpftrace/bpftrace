#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_delete)
{
  test("kprobe:f { @x[1] = 1; delete(@x, 1) }",

       NAME);
}

TEST(codegen, call_delete_deprecated)
{
  test("kprobe:f { @x[1] = 1; delete(@x[1]) }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
