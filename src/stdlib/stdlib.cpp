#include "stdlib/stdlib.h"

namespace bpftrace::stdlib {

std::string make_view(const unsigned char *v, size_t sz)
{
  return { reinterpret_cast<const char *>(v), sz };
}

// Embedded file contents.
#include "stdlib/__stddef_max_align_t.h"
#include "stdlib/base_bc.h"
#include "stdlib/base_bt.h"
#include "stdlib/base_btf.h"
#include "stdlib/float.h"
#include "stdlib/limits.h"
#include "stdlib/stdarg.h"
#include "stdlib/stdbool.h"
#include "stdlib/stddef.h"
#include "stdlib/stdint.h"

// Files is the immutable index of embedded files.
const std::map<std::string, std::string> Stdlib::files = {
  { "stdlib/base.btf", make_view(base_btf, sizeof(base_btf)) },
  { "stdlib/base.bc", make_view(base_bc, sizeof(base_bc)) },
  { "stdlib/base.bt", make_view(base_bt, sizeof(base_bt)) },
  { "include/float.h", make_view(float_h, sizeof(float_h)) },
  { "include/limits.h", make_view(limits_h, sizeof(limits_h)) },
  { "include/stdarg.h", make_view(stdarg_h, sizeof(stdarg_h)) },
  { "include/stdbool.h", make_view(stdbool_h, sizeof(stdbool_h)) },
  { "include/stddef.h", make_view(stddef_h, sizeof(stddef_h)) },
  { "include/__stddef_max_align_t.h",
    make_view(__stddef_max_align_t_h, sizeof(__stddef_max_align_t_h)) },
  { "include/stdint.h", make_view(stdint_h, sizeof(stdint_h)) },
};

} // namespace bpftrace::stdlib
