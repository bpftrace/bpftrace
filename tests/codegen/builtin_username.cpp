#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_username)
{
  test("kprobe:f { @x = username; @y = gid}",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
