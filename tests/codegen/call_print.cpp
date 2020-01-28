#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_print)
{
  test("BEGIN { @x = 1; } kprobe:f { print(@x); }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
