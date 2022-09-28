#include "elf_parser.h"
#include <elf.h>

namespace bpftrace {
namespace elf {

BpfBytecode parseBpfBytecodeFromElfObject(void *const elf)
{
  char *fileptr = (char *)elf;
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf;

  assert(ehdr->e_ident[EI_MAG0] == ELFMAG0);
  assert(ehdr->e_ident[EI_MAG1] == ELFMAG1);
  assert(ehdr->e_ident[EI_MAG2] == ELFMAG2);
  assert(ehdr->e_ident[EI_MAG3] == ELFMAG3);

  assert(ehdr->e_machine == EM_BPF);
  assert(ehdr->e_shoff != 0);
  assert(ehdr->e_shstrndx != SHN_UNDEF); // section table index for section
                                         // names

  // Our algorithm would have to advance by e_shentsize if these
  // were ever to diverge.
  assert(sizeof(Elf64_Shdr) == ehdr->e_shentsize);

  Elf64_Shdr *shdrs = (Elf64_Shdr *)(fileptr + ehdr->e_shoff);
  Elf64_Shdr *strtable_shdr = &shdrs[ehdr->e_shstrndx];
  assert(strtable_shdr->sh_type == SHT_STRTAB);
  char *strtable = fileptr + strtable_shdr->sh_offset;

  BpfBytecode result{};

  for (int i = 0; i < ehdr->e_shnum; ++i)
  {
    Elf64_Shdr *shdr = &shdrs[i];

    char *name = strtable + shdr->sh_name;
    std::vector<uint8_t> data;
    data.resize(shdr->sh_size);

    if (shdr->sh_type != SHT_NOBITS)
    {
      // NOBITS sections occupy no size on disk but take up size in
      // memory. Copy the file data for all other sections.

      std::memcpy(data.data(), fileptr + shdr->sh_offset, shdr->sh_size);
    }
    result.emplace(name, std::move(data));
  }

  return result;
}

} // namespace elf
} // namespace bpftrace