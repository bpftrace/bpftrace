#include "cxxdemangler.h"

#include <llvm/Config/llvm-config.h>
#include <llvm/Demangle/Demangle.h>

namespace bpftrace {

char* cxxdemangle(const char* mangled)
{
  return llvm::itaniumDemangle(mangled);
}

} // namespace bpftrace
