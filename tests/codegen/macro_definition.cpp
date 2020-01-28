#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, macro_definition)
{
  test("#define FOO 100\nk:f { @ = FOO }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
