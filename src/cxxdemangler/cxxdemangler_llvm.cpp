#include "cxxdemangler.h"

#include <llvm/Config/llvm-config.h>
#include <llvm/Demangle/Demangle.h>

namespace bpftrace {

std::string cxxdemangle(const char *mangled)
{
  std::string s;
#if LLVM_VERSION_MAJOR <= 16
  char *d = llvm::itaniumDemangle(mangled, nullptr, nullptr, nullptr);
#else
  char *d = llvm::itaniumDemangle(mangled);
#endif
  if (!d) {
    return s;
  }
  s = std::string(d);
  free(d);
  return s;
}

} // namespace bpftrace
