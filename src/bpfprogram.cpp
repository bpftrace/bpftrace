#include "bpfprogram.h"
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>

namespace bpftrace {

std::optional<BpfProgram> BpfProgram::CreateFromBytecode(
    const BpfBytecode &bytecode,
    const char *name,
    BPFtrace &bpftrace)
{
  if (bytecode.find(name) != bytecode.end())
  {
    return BpfProgram(bytecode, name, bpftrace);
  }
  return std::nullopt;
}

BpfProgram::BpfProgram(const BpfBytecode &bytecode,
                       const char *name,
                       BPFtrace &bpftrace)
    : bytecode_(bytecode), bpftrace_(bpftrace), name_(name), code_()
{
}

std::tuple<uint8_t *, uintptr_t> BpfProgram::getCode()
{
  if (code_.empty())
  {
    assemble();
  }
  return std::make_tuple(code_.data(), (uintptr_t)code_.size());
}

void BpfProgram::assemble()
{
  if (!code_.empty())
    return;

  auto &section = bytecode_.at(name_);
  code_.reserve(section.size());
  code_.assign(section.data(), section.data() + section.size());

  relocateMaps();
}

void BpfProgram::relocateMaps()
{
  struct bpf_insn *insns = reinterpret_cast<struct bpf_insn *>(code_.data());
  for (uintptr_t i = 0; i < code_.size() / sizeof(struct bpf_insn); ++i)
  {
    struct bpf_insn *insn = &insns[i];

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
        insn->imm = static_cast<int32_t>((*map)->mapfd_);
      else
        throw std::runtime_error(std::string("Unknown map id ") +
                                 std::to_string(mapid));

      ++i; // ldimm64 is 2 insns wide
    }
  }
}

} // namespace bpftrace
