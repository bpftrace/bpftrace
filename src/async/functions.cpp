#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <gelf.h>
#include <iostream>
#include <libelf.h>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

#include "async/functions.h"
#include "async/memory.h"
#include "async/relocations.h"
#include "util/memfd.h"

namespace bpftrace::async {

using bpftrace::util::MemFd;

char SymbolNotFoundError::ID;
char ELFError::ID;

void SymbolNotFoundError::log(llvm::raw_ostream& OS) const
{
  OS << "Symbol not found: " << symbol_name_;
}

void ELFError::log(llvm::raw_ostream& OS) const
{
  OS << "ELF error: " << elf_errmsg(err_);
}

using Reloc = RelocationHandler<bpftrace::arch::current()>;

struct Symbol {
  std::string name;
  uint64_t address;
  uint64_t size;
  int binding;
  int type;
  uint16_t section_index;
};

struct Section {
  std::string name;
  uint64_t address;
  uint64_t size;
  uint64_t offset;
  uint32_t type;
  uint64_t flags;
  void* data;
};

struct Relocation {
  uint64_t offset;
  uint32_t type;
  uint32_t symbol_index;
  int64_t addend;
};

class ELFLinker {
public:
  ELFLinker(int fd, std::map<std::string, void*>&& external_functions)
      : fd_(fd),
        elf_(nullptr),
        external_functions_(std::move(external_functions)),
        exec_region_(std::make_shared<MemoryRegion>()),
        trampoline_region_(std::make_shared<MemoryRegion>()),
        got_region_(std::make_shared<MemoryRegion>())
  {
    assert(elf_version(EV_CURRENT) != EV_NONE);
    elf_ = elf_begin(fd_, ELF_C_READ, nullptr);
  }
  ~ELFLinker()
  {
    if (elf_) {
      elf_end(elf_);
    }
  }

  Result<> parse_sections()
  {
    Elf_Scn* scn = nullptr;
    size_t shstrndx;

    if (elf_getshdrstrndx(elf_, &shstrndx) != 0) {
      return make_error<ELFError>(elf_errno());
    }

    while ((scn = elf_nextscn(elf_, scn)) != nullptr) {
      GElf_Shdr shdr;
      if (gelf_getshdr(scn, &shdr) != &shdr) {
        return make_error<ELFError>(elf_errno());
      }

      Section section;
      section.name = elf_strptr(elf_, shstrndx, shdr.sh_name);
      section.address = shdr.sh_addr;
      section.size = shdr.sh_size;
      section.offset = shdr.sh_offset;
      section.type = shdr.sh_type;
      section.flags = shdr.sh_flags;

      // Get section data
      Elf_Data* data = elf_getdata(scn, nullptr);
      if (data) {
        section.data = data->d_buf;
      } else {
        section.data = nullptr;
      }

      sections_.push_back(section);
    }

    return OK();
  }

  Result<> parse_symbols()
  {
    for (size_t i = 0; i < sections_.size(); ++i) {
      const Section& section = sections_[i];

      if (section.type == SHT_SYMTAB || section.type == SHT_DYNSYM) {
        // Find the string table for this symbol table.
        size_t strtab_index = 0;
        for (size_t j = 0; j < sections_.size(); ++j) {
          if (sections_[j].type == SHT_STRTAB &&
              sections_[j].name.find("str") != std::string::npos) {
            strtab_index = j;
            break;
          }
        }

        Elf_Scn* scn = elf_getscn(elf_, i + 1); // ELF sections are 1-indexed.
        if (!scn)
          continue;

        Elf_Data* data = elf_getdata(scn, nullptr);
        if (!data)
          continue;

        size_t symbol_count = section.size / sizeof(GElf_Sym);
        for (size_t sym_idx = 0; sym_idx < symbol_count; ++sym_idx) {
          GElf_Sym sym;
          if (gelf_getsym(data, sym_idx, &sym) != &sym) {
            continue;
          }

          Symbol symbol;
          if (strtab_index < sections_.size() && sections_[strtab_index].data) {
            const char* strtab = static_cast<const char*>(
                sections_[strtab_index].data);
            symbol.name = strtab + sym.st_name;
          }
          symbol.address = sym.st_value;
          symbol.size = sym.st_size;
          symbol.binding = GELF_ST_BIND(sym.st_info);
          symbol.type = GELF_ST_TYPE(sym.st_info);
          symbol.section_index = sym.st_shndx;

          symbols_.push_back(symbol);
        }
      }
    }

    return OK();
  }

  Result<> parse_relocations()
  {
    uint32_t text_section_index = 0;
    for (size_t i = 0; i < sections_.size(); ++i) {
      if (sections_[i].flags & SHF_EXECINSTR) {
        text_section_index = i + 1; // ELF section indices are 1-based.
        break;
      }
    }

    for (size_t i = 0; i < sections_.size(); ++i) {
      const Section& section = sections_[i];
      if (section.type == SHT_RELA) {
        Elf_Scn* scn = elf_getscn(elf_, i + 1);
        if (!scn)
          continue;

        // Get the section header to find the target section.
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) != &shdr) {
          continue;
        }

        // Check if this relocation section targets a non-text section.
        if (shdr.sh_info != text_section_index) {
          return make_error<SystemError>(
              "Only relocations targeting the .text section are supported",
              EINVAL);
        }

        Elf_Data* data = elf_getdata(scn, nullptr);
        if (!data)
          continue;

        size_t reloc_count = section.size / sizeof(GElf_Rela);
        for (size_t rel_idx = 0; rel_idx < reloc_count; ++rel_idx) {
          GElf_Rela rela;
          if (gelf_getrela(data, rel_idx, &rela) != &rela) {
            continue;
          }

          Relocation reloc;
          reloc.offset = rela.r_offset;
          reloc.type = GELF_R_TYPE(rela.r_info);
          reloc.symbol_index = GELF_R_SYM(rela.r_info);
          reloc.addend = rela.r_addend;

          relocations_.push_back(reloc);
        }
      } else if (section.type == SHT_REL) {
        Elf_Scn* scn = elf_getscn(elf_, i + 1);
        if (!scn)
          continue;

        // Get the section header to find the target section
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) != &shdr) {
          continue;
        }

        // Check if this relocation section targets a non-text section.
        if (shdr.sh_info != text_section_index) {
          return make_error<SystemError>(
              "Only relocations targeting the .text section are supported",
              EINVAL);
        }

        Elf_Data* data = elf_getdata(scn, nullptr);
        if (!data)
          continue;

        size_t reloc_count = section.size / sizeof(GElf_Rel);
        for (size_t rel_idx = 0; rel_idx < reloc_count; ++rel_idx) {
          GElf_Rel rel;
          if (gelf_getrel(data, rel_idx, &rel) != &rel) {
            continue;
          }

          Relocation reloc;
          reloc.offset = rel.r_offset;
          reloc.type = GELF_R_TYPE(rel.r_info);
          reloc.symbol_index = GELF_R_SYM(rel.r_info);
          reloc.addend = 0; // REL relocations don't have explicit addend.

          relocations_.push_back(reloc);
        }
      }
    }

    return OK();
  }

  Result<uint64_t> resolve_symbol(const std::string& symbol_name)
  {
    // First check known functions.
    auto it = external_functions_.find(symbol_name);
    if (it != external_functions_.end()) {
      return reinterpret_cast<uint64_t>(it->second);
    }

    // Then check local symbols.
    for (const Symbol& sym : symbols_) {
      if (sym.name == symbol_name && sym.section_index != SHN_UNDEF) {
        return sym.address;
      }
    }

    return make_error<SymbolNotFoundError>(symbol_name);
  }

  Result<> apply_relocations()
  {
    for (const Relocation& reloc : relocations_) {
      if (reloc.symbol_index >= symbols_.size()) {
        continue;
      }

      const Symbol& symbol = symbols_[reloc.symbol_index];
      auto symbol_addr = resolve_symbol_with_trampoline(symbol.name,
                                                        reloc.type);
      if (!symbol_addr) {
        return symbol_addr.takeError();
      }

      // Find the section containing this relocation by looking for the section
      // that contains the relocation offset (before relocation).
      Section* target_section = nullptr;
      uint64_t original_section_base = 0;

      // For PIC code, relocation offsets are relative.
      for (Section& section : sections_) {
        if (section.flags & SHF_EXECINSTR) {
          // Calculate the original section address range
          // The relocation offset should be within the original section bounds
          uint64_t section_start = original_section_base;
          uint64_t section_end = section_start + section.size;

          if (reloc.offset >= section_start && reloc.offset < section_end) {
            target_section = &section;
            break;
          }

          original_section_base += section.size;
        }
      }
      if (!target_section || !target_section->data) {
        continue;
      }

      // Apply relocation directly to the copied executable.
      Section* text_section = nullptr;
      for (Section& section : sections_) {
        if (section.flags & SHF_EXECINSTR) {
          text_section = &section;
          break;
        }
      }
      if (!text_section) {
        continue;
      }

      // Apply relocation to the copied data in executable memory.
      uint8_t* patch_location = reinterpret_cast<uint8_t*>(
                                    text_section->address) +
                                reloc.offset;
      uint64_t patch_address = text_section->address + reloc.offset;
      auto ok = Reloc::apply(reloc.type,
                             patch_location,
                             *symbol_addr,
                             reloc.addend,
                             patch_address);
      if (!ok) {
        return ok.takeError();
      }
    }
    return OK();
  }

  Result<> allocate_executable_memory()
  {
    uint64_t size = 0;
    for (const Section& section : sections_) {
      if (section.flags & SHF_EXECINSTR) {
        size += section.size;
      }
    }
    auto exec_region = MemoryRegion::allocate(size, PROT_READ | PROT_WRITE);
    if (!exec_region) {
      return exec_region.takeError();
    }
    exec_region_ = std::move(*exec_region);
    return OK();
  }

  Result<> make_memory_executable()
  {
    auto ok = exec_region_->protect(PROT_READ | PROT_EXEC);
    if (!ok) {
      return ok.takeError();
    }
    return trampoline_region_->protect(PROT_READ | PROT_EXEC);
  }

  Result<> allocate_trampoline_region()
  {
    size_t external_symbol_count = 0;
    for (const Relocation& reloc : relocations_) {
      if (reloc.symbol_index < symbols_.size()) {
        const Symbol& symbol = symbols_[reloc.symbol_index];
        if (external_functions_.contains(symbol.name)) {
          external_symbol_count++;
        }
      }
    }
    if (external_symbol_count == 0) {
      return OK(); // No trampolines needed.
    }
    auto trampoline_region = MemoryRegion::allocate(Reloc::trampoline_size() *
                                                        external_symbol_count,
                                                    PROT_READ | PROT_WRITE);
    if (!trampoline_region) {
      return trampoline_region.takeError();
    }
    trampoline_region_ = std::move(*trampoline_region);
    return OK();
  }

  Result<> allocate_got_region()
  {
    size_t got_entry_count = 0;
    for (const Relocation& reloc : relocations_) {
      if (reloc.type == R_X86_64_GOTPCREL || reloc.type == R_X86_64_GOTPCRELX) {
        got_entry_count++;
      }
    }
    if (got_entry_count == 0) {
      return OK(); // No GOT entries needed.
    }
    auto got_region = MemoryRegion::allocate(
        Reloc::trampoline_size() * bpftrace::arch::Host::kernel_ptr_width(),
        PROT_READ | PROT_WRITE);
    if (!got_region) {
      return got_region.takeError();
    }
    got_region_ = std::move(*got_region);
    return OK();
  }

  Result<> generate_trampolines()
  {
    if (trampoline_region_->size() == 0) {
      return OK(); // No trampolines needed.
    }
    uint8_t* current_trampoline = static_cast<uint8_t*>(
        trampoline_region_->addr());
    uint64_t* current_got_entry = static_cast<uint64_t*>(got_region_->addr());

    // Generate trampolines for external symbols.
    for (const Relocation& reloc : relocations_) {
      if (reloc.symbol_index < symbols_.size()) {
        const Symbol& symbol = symbols_[reloc.symbol_index];
        auto it = external_functions_.find(symbol.name);
        if (it != external_functions_.end() &&
            trampoline_addresses_.find(symbol.name) ==
                trampoline_addresses_.end()) {
          auto target_addr = reinterpret_cast<uint64_t>(it->second);
          auto trampoline_addr = reinterpret_cast<uint64_t>(current_trampoline);
          auto ok = Reloc::trampoline(current_trampoline, target_addr);
          if (!ok) {
            return ok.takeError();
          }
          trampoline_addresses_[symbol.name] = trampoline_addr;
          if (got_region_ && got_entries_.contains(symbol.name)) {
            uint64_t got_entry_addr = reinterpret_cast<uint64_t>(
                current_got_entry);
            *current_got_entry = trampoline_addr;
            got_entries_[symbol.name] = got_entry_addr;
            current_got_entry++;
          }
          current_trampoline += Reloc::trampoline_size();
        }
      }
    }
    return OK();
  }

  Result<uint64_t> resolve_symbol_with_trampoline(
      const std::string& symbol_name,
      uint32_t reloc_type = 0)
  {
    // For GOT-style relocations, return the GOT entry address (not the
    // trampoline address)
    if (reloc_type == R_X86_64_GOTPCREL || reloc_type == R_X86_64_GOTPCRELX) {
      auto got_it = got_entries_.find(symbol_name);
      if (got_it != got_entries_.end()) {
        return got_it->second;
      }
    }

    // For other relocations, use trampoline address directly.
    auto trampoline_it = trampoline_addresses_.find(symbol_name);
    if (trampoline_it != trampoline_addresses_.end()) {
      return trampoline_it->second;
    }

    // Fall back to regular symbol resolution.
    return resolve_symbol(symbol_name);
  }

  Result<> copy_sections_to_memory()
  {
    uint8_t* current_addr = reinterpret_cast<uint8_t*>(exec_region_->addr());
    for (size_t i = 0; i < sections_.size(); ++i) {
      Section& section = sections_[i];
      if (section.flags & SHF_EXECINSTR && section.data) {
        section.address = reinterpret_cast<uint64_t>(current_addr);
        memcpy(current_addr, section.data, section.size);
        current_addr += section.size;
      }
    }

    for (Symbol& symbol : symbols_) {
      // ELF section indices are 1-based, but our sections array is 0-based
      // So we need to subtract 1 to get the correct array index.
      if (symbol.section_index > 0 &&
          (symbol.section_index - 1) < static_cast<int64_t>(sections_.size())) {
        const Section& section = sections_[symbol.section_index - 1];
        if (section.flags & SHF_EXECINSTR) {
          uint64_t symbol_offset = symbol.address;
          symbol.address = section.address + symbol_offset;
        }
      }
    }

    return OK();
  }

  Result<> link()
  {
    if (!elf_) {
      return make_error<ELFError>(-1);
    }
    if (elf_kind(elf_) != ELF_K_ELF) {
      return make_error<ELFError>(-1);
    }
    for (auto fn : {
             &ELFLinker::parse_sections,
             &ELFLinker::parse_symbols,
             &ELFLinker::parse_relocations,
             &ELFLinker::allocate_executable_memory,
             &ELFLinker::copy_sections_to_memory,
             &ELFLinker::allocate_trampoline_region,
             &ELFLinker::allocate_got_region,
             &ELFLinker::generate_trampolines,
             &ELFLinker::apply_relocations,
             &ELFLinker::make_memory_executable,
         }) {
      auto ok = (this->*fn)();
      if (!ok) {
        return ok.takeError();
      }
    }
    return OK();
  }

  std::shared_ptr<MemoryRegion> exec_region() const
  {
    return exec_region_;
  }

  std::shared_ptr<MemoryRegion> trampoline_region() const
  {
    return trampoline_region_;
  }

  std::shared_ptr<MemoryRegion> got_region() const
  {
    return got_region_;
  }

  std::map<std::string, uint64_t> symbol_table() const
  {
    std::map<std::string, uint64_t> symbol_table;
    for (const Symbol& symbol : symbols_) {
      if (symbol.type == STT_FUNC && !symbol.name.empty()) {
        symbol_table[symbol.name] = symbol.address;
      }
    }
    return symbol_table;
  }

private:
  int fd_;
  Elf* elf_;
  std::vector<Section> sections_;
  std::vector<Symbol> symbols_;
  std::vector<Relocation> relocations_;
  std::map<std::string, void*> external_functions_;
  std::shared_ptr<MemoryRegion> exec_region_;
  std::shared_ptr<MemoryRegion> trampoline_region_;
  std::shared_ptr<MemoryRegion> got_region_;
  std::map<std::string, uint64_t> trampoline_addresses_;
  std::map<std::string, uint64_t> got_entries_;
};

Result<Functions> Functions::load(
    const std::span<const char>& object,
    std::map<std::string, void*> external_functions)
{
  auto file = MemFd::create("functions");
  if (!file) {
    return file.takeError();
  }
  auto ok = file->write_all(object);
  if (!ok) {
    return ok.takeError();
  }

  ELFLinker linker(file->fd(), std::move(external_functions));
  auto linkOk = linker.link();
  if (!linkOk) {
    return linkOk.takeError();
  }

  return Functions(linker.exec_region(),
                   linker.trampoline_region(),
                   linker.got_region(),
                   linker.symbol_table());
}

Result<void*> Functions::symbol(const std::string& symbol_name) const
{
  // Look up the symbol in our symbol table.
  auto it = symbol_table_.find(symbol_name);
  if (it != symbol_table_.end()) {
    return reinterpret_cast<void*>(it->second);
  }

  return make_error<SymbolNotFoundError>(symbol_name);
}

} // namespace bpftrace::async
