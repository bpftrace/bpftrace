#if HAVE_LIBDW

#include "../dwarf_common.h"
#include "common.h"

namespace bpftrace::test::codegen {

class codegen_dwarf : public test_dwarf {};

TEST_F(codegen_dwarf, map_args)
{
  // Note that this renames the function to avoid depending on
  // the variable path, to ensure codegen tests are stable.
  std::string uprobe = "f`uprobe:" + std::string(bin_) + ":func_1";
  test(uprobe + "{ @ = args }", NAME);
}

} // namespace bpftrace::test::codegen

#endif // HAVE_LIBDW
