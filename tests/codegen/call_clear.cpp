#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_clear)
{
  test("BEGIN { @x = 1; } kprobe:f { clear(@x); }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
