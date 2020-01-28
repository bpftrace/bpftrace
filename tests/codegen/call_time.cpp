#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_time)
{
  test("kprobe:f { time(); }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
