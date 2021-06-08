#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, dereference)
{
  test("kprobe:f { @x = *kptr(1234) }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
