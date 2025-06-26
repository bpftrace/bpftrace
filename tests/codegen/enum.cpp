#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, enum_declaration)
{
  test("enum { a = 42, b } k:f { @a = a; @b = b }",

       NAME);
}

} // namespace bpftrace::test::codegen
