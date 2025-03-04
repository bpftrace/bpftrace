
#include <llvm/Support/raw_os_ostream.h>

#include "util/result.h"

namespace bpftrace {

std::ostream& operator<<(std::ostream& out, const llvm::Error& err)
{
  llvm::raw_os_ostream raw_ostream(out);
  raw_ostream << err;
  raw_ostream.flush();
  return out;
}

} // namespace bpftrace
