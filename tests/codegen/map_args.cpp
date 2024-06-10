#ifdef HAVE_LIBLLDB

#include "../dwarf_common.h"
#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

class codegen_dwarf : public test_dwarf {};

TEST_F(codegen_dwarf, map_args)
{
  std::string uprobe = "uprobe:" + std::string(bin_) + ":func_1";
  test(uprobe + "{ @ = args }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace

#endif // HAVE_LIBLLDB
