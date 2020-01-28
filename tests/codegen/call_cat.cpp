#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_cat)
{
  test("kprobe:f { cat(\"/proc/loadavg\"); }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
