#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, variable_assign_string)
{
  test("kprobe:f { $var = \"blah\"; @map = $var; }",

       NAME);
}

TEST(codegen, variable_assign_string_shorter)
{
  test(R"(kprobe:f { $var = "xxxxx"; $var = "a"; @map = $var; })",

       NAME);
}

} // namespace bpftrace::test::codegen
