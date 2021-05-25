#include "relocator.h"

#include <bcc/libbpf.h>

#include "bpftrace.h"
#include "log.h"

namespace bpftrace {

Relocator::Relocator(std::tuple<uint8_t *, uintptr_t> func, BPFtrace &bpftrace)
    : insns_(reinterpret_cast<struct bpf_insn *>(std::get<0>(func))),
      nr_(std::get<1>(func) / sizeof(struct bpf_insn)),
      bpftrace_(bpftrace)
{
}

int Relocator::relocate()
{
  return 0;
}

} // namespace bpftrace
