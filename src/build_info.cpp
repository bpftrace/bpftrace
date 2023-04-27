#include <sstream>

#include "build_info.h"

namespace bpftrace {

std::string BuildInfo::report()
{
  std::stringstream buf;

  buf << "Build" << std::endl
      << "  version: " << BPFTRACE_VERSION << std::endl
      << "  LLVM: " << LLVM_VERSION_MAJOR << "." << LLVM_VERSION_MINOR << "."
      << LLVM_VERSION_PATCH << std::endl
      << "  unsafe probe: "
#ifdef HAVE_UNSAFE_PROBE
      << "yes" << std::endl;
#else
      << "no" << std::endl;
#endif
  buf << "  bfd: "
#ifdef HAVE_BFD_DISASM
      << "yes" << std::endl;
#else
      << "no" << std::endl;
#endif
  buf << "  libdw (DWARF support): "
#ifdef HAVE_LIBDW
      << "yes" << std::endl;
#else
      << "no" << std::endl;
#endif

  return buf.str();
}

} // namespace bpftrace
