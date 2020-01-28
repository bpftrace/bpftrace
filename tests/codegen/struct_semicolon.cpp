#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, struct_semicolon)
{
  test("struct Foo { int x, y; char *str; };"
       "k:f"
       "{"
       "  printf(\"%s\\n\", ustack);"
       "}",
       std::string(NAME) + "_1");

  test("struct Foo { int x, y; char *str; }"
       "k:f"
       "{"
       "  printf(\"%s\\n\", ustack);"
       "}",
       std::string(NAME) + "_2");
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
