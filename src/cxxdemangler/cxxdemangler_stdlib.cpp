#include "cxxdemangler.h"

#include <cxxabi.h>

namespace bpftrace {

char* cxxdemangle(const char* mangled)
{
  return abi::__cxa_demangle(mangled, nullptr, nullptr, nullptr);
}

} // namespace bpftrace
