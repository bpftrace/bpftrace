#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_ntop_key)
{
  test("kprobe:f { @x[ntop(2, 0xFFFFFFFF)] = count()}",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
