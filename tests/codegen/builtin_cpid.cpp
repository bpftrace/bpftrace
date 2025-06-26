#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, builtin_cpid)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->child_ = std::make_unique<MockChildProc>("");
  bpftrace->helper_check_level_ = 0;

  test(*bpftrace, "kprobe:f { @ = cpid }", NAME);
}

} // namespace bpftrace::test::codegen
