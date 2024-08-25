#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_path_with_optional_size)
{
  test("kfunc:filp_close { path(args->filp->f_path, 48); }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
