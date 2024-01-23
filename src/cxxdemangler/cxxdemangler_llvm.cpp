#include "cxxdemangler.h"

#include <llvm/Config/llvm-config.h>
#include <llvm/Demangle/Demangle.h>

namespace bpftrace {

char* cxxdemangle(const char* mangled)
{
#if LLVM_VERSION_MAJOR <= 16
  return llvm::itaniumDemangle(mangled, nullptr, nullptr, nullptr);
#else
  return llvm::itaniumDemangle(mangled);
#endif
}

} // namespace bpftrace
