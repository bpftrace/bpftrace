#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_usym_key)
{
  test("kprobe:f { @x[usym(0)] = 1; }",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
