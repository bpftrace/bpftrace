#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_path_with_optional_size)
{
  test("fentry:filp_close { path((uint8 *)0, 48); }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
