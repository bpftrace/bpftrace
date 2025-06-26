#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_sizeof)
{
  test("struct Foo { int x; char c; } BEGIN { @x = sizeof(struct Foo) }",

       NAME);
}

} // namespace bpftrace::test::codegen
