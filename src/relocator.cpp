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
  for (uintptr_t i = 0; i < nr_; ++i)
  {
    struct bpf_insn *insn = &insns_[i];

    // Relocate mapid -> mapfd
    //
    // This relocation keeps codegen independent of runtime state (such as FD
    // numbers). This helps make codegen tests more reliable and enables
    // features such as AOT compilation.
    if (insn->code == BPF_DW && (insn->src_reg == BPF_PSEUDO_MAP_FD ||
                                 insn->src_reg == BPF_PSEUDO_MAP_VALUE))
    {
      auto mapid = insn->imm;
      auto map = bpftrace_.maps[mapid];
      if (map)
      {
        insn->imm = static_cast<int32_t>((*map)->mapfd_);
      }
      else
      {
        LOG(ERROR) << "Failed to relocate mapid=" << mapid << ": ID unknown";
        return 1;
      }

      ++i; // ldimm64 is 2 insns wide
    }
  }

  return 0;
}

} // namespace bpftrace
