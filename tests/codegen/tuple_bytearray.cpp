#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, tuple_bytearray)
{
  test(R"_(k:f { @t = ((uint8)1, usym(reg("ip")), 10); })_",

       NAME);
}

} // namespace bpftrace::test::codegen
