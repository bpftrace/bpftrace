#include "cxxdemangler.h"

#include <cxxabi.h>

namespace bpftrace {

std::string cxxdemangle(const char *mangled)
{
  std::string s;
  char *d = abi::__cxa_demangle(mangled, nullptr, nullptr, nullptr);
  if (!d)
    return s;
  s = std::string(d);
  free(d);
  return s;
}

} // namespace bpftrace
