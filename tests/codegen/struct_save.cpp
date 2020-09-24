#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, struct_save)
{
  test("struct Foo { int x, y, z; }"
       "kprobe:f"
       "{"
       "  @foo = *(struct Foo*)arg0;"
       "}",
       std::string(NAME) + "_1");

  test("struct Foo { int x, y, z; }"
       "kprobe:f"
       "{"
       "  @foo = *(struct Foo*)arg0;"
       "}",
       std::string(NAME) + "_2");
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
