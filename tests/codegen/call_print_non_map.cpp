#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

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
} // namespace codegen
} // namespace test
} // namespace bpftrace
