#include "bpfprogram.h"

#include <optional>
#include <stdexcept>
#include <tuple>

namespace bpftrace {

std::optional<BpfProgram> BpfProgram::CreateFromBytecode(
    const BpfBytecode &bytecode,
    const std::string &name,
    MapManager &maps)
{
  if (bytecode.find(name) != bytecode.end())
  {
    return BpfProgram(bytecode, name, maps);
  }
  return std::nullopt;
}

BpfProgram::BpfProgram(const BpfBytecode &bytecode,
                       const std::string &name,
                       MapManager &maps)
    : bytecode_(bytecode), maps_(maps), name_(name), code_()
{
}

const std::vector<uint8_t> &BpfProgram::getCode()
{
  return code_;
}

const std::vector<uint8_t> &BpfProgram::getBTF()
{
  return bytecode_.at(".BTF");
}

void BpfProgram::assemble()
{
  if (!code_.empty())
    return;

  code_ = bytecode_.at(name_);

  relocateMaps();
}

void BpfProgram::relocateMaps()
{
  struct bpf_insn *insns = reinterpret_cast<struct bpf_insn *>(code_.data());
  size_t insn_cnt = code_.size() / sizeof(struct bpf_insn);
  for (uintptr_t i = 0; i < insn_cnt; ++i)
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
      auto map = maps_[mapid];
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
