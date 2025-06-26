#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_path)
{
  test("fentry:filp_close { path((uint8 *)0); }", NAME);
}

} // namespace bpftrace::test::codegen
