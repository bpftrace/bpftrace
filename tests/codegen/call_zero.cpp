#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_zero)
{
  test("BEGIN { @x = 1; } kprobe:f { zero(@x); }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
