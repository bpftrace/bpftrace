#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, if_else_variable)
{
  test("kprobe:f { if (pid > 10000) { $s = 10 } else { $s = 20 } printf(\"s = "
       "%d\", $s) }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
