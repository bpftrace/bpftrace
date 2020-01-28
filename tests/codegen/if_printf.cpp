#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, if_printf)
{
  test("kprobe:f { if (pid > 10000) { printf(\"%d is high\\n\", pid); } }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
