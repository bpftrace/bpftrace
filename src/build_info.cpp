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
#ifdef LLVM_ORC_V2
      << "  ORC: v2" << std::endl
#endif
      << "  foreach_sym: "
#ifdef HAVE_BCC_ELF_FOREACH_SYM
      << "yes" << std::endl
#else
      << "no" << std::endl
#endif
      << "  unsafe uprobe: "
#ifdef HAVE_UNSAFE_UPROBE
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
  buf << "  bpf_attach_kfunc: "
#ifdef HAVE_BCC_KFUNC
      << "yes" << std::endl;
#else
      << "no" << std::endl;
#endif
  buf << "  bcc_usdt_addsem: "
#ifdef HAVE_BCC_USDT_ADDSEM
      << "yes" << std::endl;
#else
      << "no" << std::endl;
#endif
  buf << "  bcc bpf_attach_uprobe refcount: "
#ifdef LIBBCC_ATTACH_UPROBE_SEVEN_ARGS_SIGNATURE
      << "yes" << std::endl;
#else
      << "no" << std::endl;
#endif
  buf << "  libbpf: "
#ifdef HAVE_LIBBPF
      << "yes" << std::endl;
#else
      << "no" << std::endl;
#endif
  buf << "  libbpf btf dump: "
#ifdef HAVE_LIBBPF_BTF_DUMP
      << "yes" << std::endl;
#else
      << "no" << std::endl;
#endif
  buf << "  libbpf btf dump type decl: "
#ifdef HAVE_LIBBPF_BTF_DUMP_EMIT_TYPE_DECL
      << "yes" << std::endl;
#else
      << "no" << std::endl;
#endif

  return buf.str();
}

} // namespace bpftrace
