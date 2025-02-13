#include <bcc/bcc_syms.h>

#include "config.h"
#include "usyms.h"

#include "scopeguard.h"

namespace bpftrace {

Usyms::Usyms(const Config &config) : config_(config)
{
}

Usyms::~Usyms()
{
  for (const auto &pair : exe_sym_) {
    if (pair.second.second)
      bcc_free_symcache(pair.second.second, pair.second.first);
  }

  for (const auto &pair : pid_sym_) {
    if (pair.second)
      bcc_free_symcache(pair.second, pair.first);
  }
}

void Usyms::cache(const std::string &elf_file)
{
  auto cache_type = config_.get(ConfigKeyUserSymbolCacheType::default_);
  // preload symbol table for executable to make it available even if the
  // binary is not present at symbol resolution time
  // note: this only makes sense with ASLR disabled, since with ASLR offsets
  // might be different
  if (cache_type == UserSymbolCacheType::per_program &&
      symbol_table_cache_.find(elf_file) == symbol_table_cache_.end())
    symbol_table_cache_[elf_file] = get_symbol_table_for_elf(elf_file);

  if (cache_type == UserSymbolCacheType::per_pid)
    // preload symbol tables from running processes
    // this allows symbol resolution for processes that are running at probe
    // attach time, but not at symbol resolution time, even with ASLR
    // enabled, since BCC symcache records the offsets
    for (int pid : get_pids_for_program(elf_file))
      pid_sym_[pid] = bcc_symcache_new(pid, &get_symbol_opts());
}

std::string Usyms::resolve(uint64_t addr,
                           int32_t pid,
                           const std::string &pid_exe,
                           bool show_offset,
                           bool show_module)
{
  auto cache_type = config_.get(ConfigKeyUserSymbolCacheType::default_);
  struct bcc_symbol usym;
  std::ostringstream symbol;
  void *psyms = nullptr;

  if (cache_type == UserSymbolCacheType::per_program) {
    if (!pid_exe.empty()) {
      // try to resolve symbol directly from program file
      // this might work when the process does not exist anymore, but cannot
      // resolve all symbols, e.g. those in a dynamically linked library
      std::map<uintptr_t, elf_symbol, std::greater<>> &symbol_table =
          symbol_table_cache_.find(pid_exe) != symbol_table_cache_.end()
              ? symbol_table_cache_[pid_exe]
              : (symbol_table_cache_[pid_exe] = get_symbol_table_for_elf(
                     pid_exe));
      auto sym = symbol_table.lower_bound(addr);
      // address has to be either the start of the symbol (for symbols of
      // length 0) or in [start, end)
      if (sym != symbol_table.end() &&
          (addr == sym->second.start ||
           (addr >= sym->second.start && addr < sym->second.end))) {
        symbol << sym->second.name;
        if (show_offset)
          symbol << "+" << addr - sym->second.start;
        if (show_module)
          symbol << " (" << pid_exe << ")";
        return symbol.str();
      }
    }
    if (exe_sym_.find(pid_exe) == exe_sym_.end()) {
      // not cached, create new ProcSyms cache
      psyms = bcc_symcache_new(pid, &get_symbol_opts());
      exe_sym_[pid_exe] = std::make_pair(pid, psyms);
    } else {
      psyms = exe_sym_[pid_exe].second;
    }
  } else if (cache_type == UserSymbolCacheType::per_pid) {
    // cache user symbols per pid
    if (pid_sym_.find(pid) == pid_sym_.end()) {
      // not cached, create new ProcSyms cache
      psyms = bcc_symcache_new(pid, &get_symbol_opts());
      pid_sym_[pid] = psyms;
    } else {
      psyms = pid_sym_[pid];
    }
  } else {
    // no user symbol caching, create new bcc cache
    psyms = bcc_symcache_new(pid, &get_symbol_opts());
  }

  if (psyms && bcc_symcache_resolve(psyms, addr, &usym) == 0) {
    SCOPE_EXIT
    {
      // This is a horrible hack to work around the fact that
      // bcc does not tell if you if demangling succeeded.
      // B/c if demangling failed, it returns a string that
      // you cannot free.
      //
      // This relies on the fact that bcc will not change the
      // `demangle_name = name` fallback. Since blazesym is
      // coming (written 2/4/25), this should be fine for now.
      if (usym.demangle_name != usym.name)
        ::free(const_cast<char *>(usym.demangle_name));
    };
    if (config_.get(ConfigKeyBool::cpp_demangle))
      symbol << usym.demangle_name;
    else
      symbol << usym.name;
    if (show_offset)
      symbol << "+" << usym.offset;
    if (show_module)
      symbol << " (" << usym.module << ")";
  } else {
    symbol << reinterpret_cast<void *>(addr);
    if (show_module)
      symbol << " ([unknown])";
  }

  if (cache_type == UserSymbolCacheType::none)
    bcc_free_symcache(psyms, pid);

  return symbol.str();
}

struct bcc_symbol_option &Usyms::get_symbol_opts()
{
  static struct bcc_symbol_option symopts = {
    .use_debug_file = 1,
    .check_debug_file_crc = 1,
    .lazy_symbolize = config_.get(ConfigKeyBool::lazy_symbolication) ? 1 : 0,
    .use_symbol_type = BCC_SYM_ALL_TYPES,
  };

  return symopts;
}

} // namespace bpftrace
