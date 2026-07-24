#include <bcc/bcc_elf.h>
#include <bcc/bcc_syms.h>
#include <cassert>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <gelf.h>
#include <glob.h>
#include <libelf.h>
#include <link.h>
#include <linux/limits.h>
#include <linux/version.h>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <zlib.h>

#include "util/symbols.h"

namespace bpftrace::util {

char SymbolError::ID;

std::map<uintptr_t, elf_symbol, std::greater<>> get_symbol_table_for_elf(
    const std::string &elf_file)
{
  std::map<uintptr_t, elf_symbol, std::greater<>> symbol_table;

  bcc_elf_symcb sym_resolve_callback = [](const char *name,
                                          uint64_t start,
                                          uint64_t length,
                                          void *payload) {
    auto *symbol_table =
        static_cast<std::map<uintptr_t, elf_symbol, std::greater<>> *>(payload);
    symbol_table->insert({ start,
                           { .name = std::string(name),
                             .start = start,
                             .end = start + length } });
    return 0;
  };
  struct bcc_symbol_option option;
  memset(&option, 0, sizeof(option));
  option.use_symbol_type = BCC_SYM_ALL_TYPES ^ (1 << STT_NOTYPE);
  bcc_elf_foreach_sym(
      elf_file.c_str(), sym_resolve_callback, &option, &symbol_table);

  return symbol_table;
}

std::pair<std::string, std::string> split_symbol_module(
    const std::string &symbol)
{
  assert(!symbol.empty());

  if (symbol[symbol.size() - 1] != ']')
    return { symbol, "vmlinux" };

  size_t idx = symbol.rfind(" [");
  assert(idx != std::string::npos);

  return { symbol.substr(0, idx),
           symbol.substr(idx + strlen(" ["),
                         symbol.length() - idx - strlen(" []")) };
}

// Usually the /sys/kernel/debug/kprobes/blacklist file.
// Format example:
// 0xffffffff85201511-0xffffffff8520152f	first_nmi
// 0xffffffffc17e9373-0xffffffffc17e94ff	vmx_vmexit [kvm_intel]
// The outputs are:
// { "0xffffffff85201511-0xffffffff8520152f", "first_nmi", "" }
// { "0xffffffffc17e9373-0xffffffffc17e94ff", "vmx_vmexit", "kvm_intel" }
std::tuple<std::string, std::string, std::string> split_addrrange_symbol_module(
    const std::string &symbol)
{
  size_t idx1 = symbol.rfind("\t");
  size_t idx2 = symbol.rfind(" [");

  if (idx2 == std::string::npos)
    return { symbol.substr(0, idx1),
             symbol.substr(idx1 + strlen("\t"),
                           symbol.length() - idx1 - strlen("\t")),
             "vmlinux" };

  return { symbol.substr(0, idx1),
           symbol.substr(idx1 + strlen("\t"), idx2 - idx1 - strlen("\t")),
           symbol.substr(idx2 + strlen(" ["),
                         symbol.length() - idx2 - strlen(" []")) };
}

struct resolve_symbols_data {
  const std::set<std::string> &names;
  std::vector<Symbol> &symbols;
};

static int resolve_symbols_cb(const char *symname,
                              uint64_t start,
                              uint64_t size,
                              void *p)
{
  auto *data = static_cast<struct resolve_symbols_data *>(p);

  if (data->names.contains(symname)) {
    data->symbols.push_back({ .name = symname, .start = start, .size = size });
  }

  return 0;
}

static int load_section_cb(uint64_t v_addr,
                           uint64_t mem_sz,
                           uint64_t file_offset,
                           void *p)
{
  auto *syms = static_cast<std::vector<Symbol> *>(p);

  for (auto &sym : *syms) {
    if (sym.start >= v_addr && sym.start < (v_addr + mem_sz)) {
      sym.file_offset = sym.start - v_addr + file_offset;
    }
  }

  return 0;
}

Result<std::vector<Symbol>> resolve_symbols(const std::string &path,
                                            const std::set<std::string> &names)
{
  std::vector<Symbol> symbols;
  struct bcc_symbol_option option;
  memset(&option, 0, sizeof(option));
  option.use_debug_file = 1;
  option.use_symbol_type = BCC_SYM_ALL_TYPES ^ (1 << STT_NOTYPE);

  struct resolve_symbols_data data = {
    .names = names,
    .symbols = symbols,
  };

  int err = bcc_elf_foreach_sym(
      path.c_str(), resolve_symbols_cb, &option, &data);
  if (err) {
    return make_error<SymbolError>("Failed to list symbols in " + path);
  }

  err = bcc_elf_foreach_load_section(path.c_str(), load_section_cb, &symbols);
  if (err) {
    return make_error<SymbolError>("Failed to resolve symbol offsets in " +
                                   path);
  }

  return symbols;
}

bool symbol_has_cpp_mangled_signature(const std::string &sym_name)
{
  return !sym_name.rfind("_Z", 0) || !sym_name.rfind("____Z", 0);
}

} // namespace bpftrace::util
