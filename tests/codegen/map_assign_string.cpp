#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, map_assign_string)
{
  test("kprobe:f { @x = \"blah\"; }",

       NAME);
}

TEST(codegen, map_assign_string_shorter)
{
  test("kprobe:f { @x = \"xxxxx\"; @x = \"a\"; }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
