#include "rustdemangler.h"

#include <llvm/Config/llvm-config.h>
#include <llvm/Demangle/Demangle.h>

namespace bpftrace {

std::string rustdemangle(const char *mangled)
{
  std::string s;
  char *d = llvm::rustDemangle(mangled);
  if (!d)
    return s;
  s = std::string(d);
  free(d);
  return s;
}

} // namespace bpftrace
