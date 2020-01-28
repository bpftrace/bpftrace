#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, enum_declaration)
{
  test("enum { a = 42, b } k:f { @a = a; @b = b }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
