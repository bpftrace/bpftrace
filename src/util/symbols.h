#pragma once

#include <cstdint>
#include <map>
#include <string>

namespace bpftrace::util {

struct symbol {
  std::string name;
  uint64_t start;
  uint64_t size;
  uint64_t address;
};

inline int sym_name_cb(const char *symname,
                       uint64_t start,
                       uint64_t size,
                       void *p)
{
  auto *sym = static_cast<struct symbol *>(p);

  if (sym->name == symname) {
    sym->start = start;
    sym->size = size;
    return -1;
  }

  return 0;
}

inline int sym_address_cb(const char *symname,
                          uint64_t start,
                          uint64_t size,
                          void *p)
{
  auto *sym = static_cast<struct symbol *>(p);

  // When size is 0, then [start, start + size) = [start, start) = ø.
  // So we need a special case when size=0, but address matches the symbol's
  if (sym->address == start ||
      (sym->address > start && sym->address < (start + size))) {
    sym->start = start;
    sym->size = size;
    sym->name = symname;
    return -1;
  }

  return 0;
}

struct elf_symbol {
  std::string name;
  uintptr_t start;
  uintptr_t end;
};

// Get all symbols from an ELF module together with their address ranges in
// the form of a map sorted by start address.
// Note: the map uses std::greater as comparator to allow resolving of an
// address inside a range using std::map::lower_bound.
std::map<uintptr_t, elf_symbol, std::greater<>> get_symbol_table_for_elf(
    const std::string &elf_file);

bool symbol_has_cpp_mangled_signature(const std::string &sym_name);

std::pair<std::string, std::string> split_symbol_module(
    const std::string &symbol);

std::tuple<std::string, std::string, std::string> split_addrrange_symbol_module(
    const std::string &symbol);

} // namespace bpftrace::util
