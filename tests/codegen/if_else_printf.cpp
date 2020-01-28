#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, if_else_printf)
{
  test("kprobe:f { if (pid > 10) { printf(\"hi\\n\"); } else "
       "{printf(\"hello\\n\")} }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
