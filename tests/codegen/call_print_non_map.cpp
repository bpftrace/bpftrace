#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_print_int)
{
  test("k:f { print(3) }",

       NAME);
}

TEST(codegen, call_print_composit)
{
  test("k:f { print((1,\"abc\")) }",

       NAME);
}

TEST(codegen, call_print_inside_print)
{
  test("k:f { print({ $x = 1; print(\"bob\"); $x > 1 }); }",

       NAME);
}

} // namespace bpftrace::test::codegen
