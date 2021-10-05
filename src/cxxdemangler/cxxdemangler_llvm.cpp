#include "cxxdemangler.h"

#include <llvm/Demangle/Demangle.h>

namespace bpftrace {

char* cxxdemangle(const char* mangled)
{
  return llvm::itaniumDemangle(mangled, nullptr, nullptr, nullptr);
}

} // namespace bpftrace
