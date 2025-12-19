#include <llvm/Config/llvm-config.h>
#include <sstream>

#include "build_info.h"
#include "dwunwind.h"

#include "version.h"

namespace bpftrace {

std::string BuildInfo::report()
{
  std::stringstream buf;

  buf << "Build" << std::endl
      << "  version: " << BPFTRACE_VERSION << std::endl
      << "  LLVM: " << LLVM_VERSION_MAJOR << "." << LLVM_VERSION_MINOR << "."
      << LLVM_VERSION_PATCH << std::endl
      << "  bfd: "
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
  buf << "  libsystemd (systemd notify support): "
#ifdef HAVE_LIBSYSTEMD
      << "yes" << std::endl;
#else
      << "no" << std::endl;
#endif
  buf << "  blazesym (advanced symbolization): "
#ifdef HAVE_BLAZESYM
      << "yes" << std::endl;
#else
      << "no" << std::endl;
#endif
  buf << "  dwunwind (DWARF stack unwinding): "
#ifdef DWUNWIND
      << "yes" << std::endl;
#else
      << "no" << std::endl;
#endif

  return buf.str();
}

} // namespace bpftrace
