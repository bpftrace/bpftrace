#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, tuple_bytearray)
{
  test(R"_(k:f { @t = ((uint8)1, usym(reg("ip")), 10); })_",

       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
