#include "stdlib/stdlib.h"

namespace bpftrace::stdlib {

std::string make_view(const unsigned char* v, size_t sz)
{
  return { reinterpret_cast<const char*>(v), sz };
}

// Embedded file contents.
#include "stdlib/base_bc.h"
#include "stdlib/base_bt.h"
#include "stdlib/base_btf.h"

// Files is the immutable index of embedded files.
const std::map<std::string, std::string> Stdlib::files = {
  { "stdlib/base.btf", make_view(base_btf, sizeof(base_btf)) },
  { "stdlib/base.bc", make_view(base_bc, sizeof(base_bc)) },
  { "stdlib/base.bt", make_view(base_bt, sizeof(base_bt)) },
};

} // namespace bpftrace::stdlib
