#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_path_with_optional_size)
{
  test("fentry:filp_close { path((uint8 *)0, 48); }", NAME);
}

} // namespace bpftrace::test::codegen
