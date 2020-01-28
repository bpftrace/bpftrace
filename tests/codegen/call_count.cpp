#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_count)
{
  test("kprobe:f { @x = count() }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
