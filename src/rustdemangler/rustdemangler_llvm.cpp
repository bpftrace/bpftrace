#include "rustdemangler.h"

#include <llvm/Config/llvm-config.h>
#include <llvm/Demangle/Demangle.h>

namespace bpftrace {

char* rustdemangle(const char* mangled)
{
  return llvm::rustDemangle(mangled);
}

} // namespace bpftrace
