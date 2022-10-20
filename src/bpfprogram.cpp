#include "bpfprogram.h"
#include "log.h"

#include <bcc/libbpf.h>
#include <cstring>
#include <elf.h>
#include <linux/bpf.h>
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

  relocateInsns();
  relocateMaps();
}

void BpfProgram::relocateInsns()
{
  std::string relsecname = std::string(".rel") + name_;
  if (bytecode_.find(relsecname) != bytecode_.end())
  {
    // There's a relocation section for our program.
    //
    // Relocation support is incomplete, only ld_imm64 + R_BPF_64_64 is
    // supported to make pointers to subprog callbacks possible.
    //
    // In practice, we append the entire .text section and relocate against it.

    auto seciter = bytecode_.find(".text");
    if (seciter == bytecode_.end())
      throw std::logic_error(
          "Relocation section present but no .text, this is unsupported");
    auto &text = seciter->second;
    auto &relsec = bytecode_.find(relsecname)->second;
    auto &symtab = bytecode_.find(".symtab")->second;

    // Step 1: append .text
    text_offset_ = code_.size();
    code_.resize(code_.size() + text.size());
    std::memcpy(code_.data() + text_offset_, text.data(), text.size());

    auto *insns = reinterpret_cast<struct bpf_insn *>(code_.data());

    // Step 2: relocate our program
    for (auto *ptr = relsec.data(); ptr < relsec.data() + relsec.size();
         ptr += sizeof(Elf64_Rel))
    {
      auto *rel = reinterpret_cast<const Elf64_Rel *>(ptr);
      uint32_t reltype = rel->r_info & 0xFFFFFFFF;
      uint32_t relsym = rel->r_info >> 32;

      if (reltype != R_BPF_64_64)
        throw std::invalid_argument("Unsupported relocation type");

      // Our program is at the beginning, so the offset is correct.
      auto rel_offset = rel->r_offset;
      auto insn_offset = rel_offset / sizeof(bpf_insn);
      auto *insn = &insns[insn_offset];
      if (insn->code != (BPF_LD | BPF_DW | BPF_IMM))
      {
        LOG(ERROR) << "Cannot relocate insn code " << insn->code << " ld "
                   << (insn->code & BPF_LD) << " dw " << (insn->code & BPF_DW)
                   << " imm " << (insn->code & BPF_IMM);
        throw std::invalid_argument("Unsupported relocated instruction");
      }

      auto *sym = &reinterpret_cast<const Elf64_Sym *>(symtab.data())[relsym];
      auto symtype = ELF64_ST_TYPE(sym->st_info);
      if (symtype != STT_FUNC && symtype != STT_SECTION)
      {
        LOG(ERROR) << "Relocation in " << relsecname << " type " << reltype
                   << " sym " << relsym << " type " << symtype;
        throw std::invalid_argument(
            "Unsupported symbol type referenced in relocation");
      }

      // Assume sym->st_shndx corresponds to .text, therefore symbol value is
      // an offset from text_offset_.
      //
      // Relocate via direct instruction manipulation instead of the
      // relocation entry for readibility purposes.
      //
      // This is a hack. We shouldn't do this. However, we don't actually have
      // the ELF section table to determine if the relocation actually refers
      // to .text
      auto target_insn = (text_offset_ + sym->st_value + insn->imm) /
                         sizeof(struct bpf_insn);
      insn->src_reg = BPF_PSEUDO_FUNC;
      insn->imm = (target_insn - insn_offset - 1); // jump offset
    }

    // Step 3: relocate .text, if necessary. TODO.
    bool need_text_rels = text_offset_ > 0 &&
                          bytecode_.find(".rel.text") != bytecode_.end();
    if (need_text_rels)
      throw std::logic_error("Relocations in .text are not implemented yet");
  }
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
