#include "stdlib/stdlib.h"

namespace bpftrace::stdlib {

std::string make_view(const unsigned char* v)
{
  return reinterpret_cast<const char*>(v);
}

// Embedded file contents.
#include "stdlib/base_bc.h"
#include "stdlib/base_btf.h"

// Files is the immutable index of embedded files.
const std::map<std::string, std::string> Stdlib::files = {
  { "stdlib/base.btf", make_view(base_btf) },
  { "stdlib/base.bc", make_view(base_bc) },
};

} // namespace bpftrace::stdlib
