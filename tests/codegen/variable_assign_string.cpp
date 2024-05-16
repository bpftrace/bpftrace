#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, variable_assign_string)
{
  test("kprobe:f { $var = \"blah\"; @map = $var; }",

       NAME);
}

TEST(codegen, variable_assign_string_shorter)
{
  test("kprobe:f { $var = \"xxxxx\"; $var = \"a\"; @map = $var; }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
