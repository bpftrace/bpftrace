#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_curtask)
{
  test("kprobe:f { @x = curtask }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
