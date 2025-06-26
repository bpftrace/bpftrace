#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_uptr)
{
  test("k:f { @=*uptr((int16*) arg0 ); }", std::string(NAME) + "_1");
  test("k:f { @=*uptr((int32*) arg0 ); }", std::string(NAME) + "_2");
}

} // namespace bpftrace::test::codegen
