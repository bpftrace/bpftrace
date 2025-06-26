#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, macro_definition)
{
  test("#define FOO 100\nk:f { @ = FOO }",

       NAME);
}

} // namespace bpftrace::test::codegen
