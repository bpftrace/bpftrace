#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, map_assign_string)
{
  test("kprobe:f { @x = \"blah\"; }",

       NAME);
}

TEST(codegen, map_assign_string_shorter)
{
  test(R"(kprobe:f { @x = "xxxxx"; @x = "a"; })",

       NAME);
}

} // namespace bpftrace::test::codegen
