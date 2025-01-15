#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_path)
{
  test("fentry:filp_close { path((uint8 *)0); }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
