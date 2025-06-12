#include <iostream>

#include "arch/arch.h"

namespace bpftrace::arch {

std::ostream& operator<<(std::ostream& out, Machine m)
{
  switch (m) {
    case Machine::X86_64:
      out << "x86_64";
      break;
    case Machine::ARM:
      out << "arm";
      break;
    case Machine::ARM64:
      out << "arm64";
      break;
    case Machine::S390X:
      out << "s390x";
      break;
    case Machine::PPC64:
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
      out << "ppc64le";
#else
      out << "ppc64";
#endif // __BYTE_ORDER__
      break;
    case Machine::MIPS64:
      out << "mips64";
      break;
    case Machine::RISCV64:
      out << "riscv64";
      break;
    case Machine::LOONGARCH64:
      out << "loongarch64";
      break;
  }
  return out;
}

} // namespace bpftrace::arch
