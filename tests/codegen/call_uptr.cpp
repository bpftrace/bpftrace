#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_uptr)
{
  test("k:f { @=*uptr((int16*) arg0 ); }", std::string(NAME) + "_1");
  test("k:f { @=*uptr((int32*) arg0 ); }", std::string(NAME) + "_2");
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
