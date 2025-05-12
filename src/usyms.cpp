#include "types.h"
#include <bcc/bcc_elf.h>
#include <bcc/bcc_syms.h>
#include <blazesym.h>
#include <sstream>

#include "config.h"
#include "scopeguard.h"
#include "usyms.h"
#include "util/symbols.h"
#include "util/system.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

namespace {
std::string stringify_addr(uint64_t addr, bool perf_mode)
{
  std::ostringstream symbol;
  symbol << reinterpret_cast<void *>(addr);
  if (perf_mode)
    symbol << " ([unknown])";
  return symbol.str();
}

std::string stringify_sym(const char *name,
                          const blaze_symbolize_code_info *code_info,
                          uint64_t offset,
                          bool show_offset,
                          const char *sym_module,
                          bool perf_mode,
                          bool is_inlined)
{
  std::ostringstream symbol;

  if (is_inlined && !perf_mode) {
    symbol << "[inlined] ";
  }

  symbol << name;

  if (show_offset) {
    symbol << "+" << offset;
  }

  if (perf_mode) {
    if (sym_module != nullptr)
      symbol << " (" << sym_module << ")";
    else if (is_inlined)
      symbol << " (inlined)";
    else
      symbol << " ([unknown])";

    // Don't add the file/line if we're in perf mode
    return symbol.str();
  }

  if (code_info != nullptr) {
    if (code_info->dir != nullptr && code_info->file != nullptr) {
      symbol << "@" << code_info->dir << "/" << code_info->file << ":"
             << code_info->line;
    } else if (code_info->file != nullptr) {
      symbol << "@" << code_info->file << ":" << code_info->line;
    }
  }

  return symbol.str();
}

void add_symbols(const blaze_sym *sym,
                 bool show_offset,
                 bool perf_mode,
                 std::vector<std::string> &str_syms)
{
  if (sym == nullptr || sym->name == nullptr) {
    return;
  }

  const struct blaze_symbolize_inlined_fn *inlined;

  // bpftrace prints stacks leaf first so the inlined functions
  // need to come first in the list (and in reverse order)
  for (int j = static_cast<int>(sym->inlined_cnt) - 1; j >= 0; j--) {
    inlined = &sym->inlined[j];
    if (inlined != nullptr) {
      str_syms.push_back(stringify_sym(inlined->name,
                                       &inlined->code_info,
                                       0,
                                       false,
                                       nullptr,
                                       perf_mode,
                                       true));
    }
  }

  str_syms.push_back(stringify_sym(sym->name,
                                   &sym->code_info,
                                   sym->offset,
                                   show_offset,
                                   sym->module,
                                   perf_mode,
                                   false));
}
} // namespace

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

  if (symbolizer_)
    blaze_symbolizer_free(symbolizer_);
}

void Usyms::cache_bcc(const std::string &elf_file)
{
  const auto cache_type = config_.user_symbol_cache_type;
  // preload symbol table for executable to make it available even if the
  // binary is not present at symbol resolution time
  // note: this only makes sense with ASLR disabled, since with ASLR offsets
  // might be different
  if (cache_type == UserSymbolCacheType::per_program &&
      !symbol_table_cache_.contains(elf_file))
    symbol_table_cache_[elf_file] = util::get_symbol_table_for_elf(elf_file);

  if (cache_type == UserSymbolCacheType::per_pid)
    // preload symbol tables from running processes
    // this allows symbol resolution for processes that are running at probe
    // attach time, but not at symbol resolution time, even with ASLR
    // enabled, since BCC symcache records the offsets
    for (int pid : util::get_pids_for_program(elf_file))
      pid_sym_[pid] = bcc_symcache_new(pid, &get_symbol_opts());
}

struct blaze_symbolizer *Usyms::create_symbolizer() const
{
  blaze_symbolizer_opts opts = {
    .type_size = sizeof(opts),
    .code_info = config_.show_debug_info,
    .inlined_fns = config_.show_debug_info,
    .demangle = config_.cpp_demangle,
  };
  return blaze_symbolizer_new_opts(&opts);
}

void Usyms::cache_blazesym(const std::string &elf_file)
{
  auto cache_type = config_.user_symbol_cache_type;
  if (cache_type == UserSymbolCacheType::none)
    return;

  if (symbolizer_ == nullptr) {
    symbolizer_ = create_symbolizer();
    if (symbolizer_ == nullptr)
      return;
  }

  // preload symbol table for executable to make it available even if the
  // binary is not present at symbol resolution time
  // note: this only makes sense with ASLR disabled, since with ASLR offsets
  // might be different
  if (cache_type == UserSymbolCacheType::per_program) {
    blaze_cache_src_elf cache = {
      .type_size = sizeof(cache),
      .path = elf_file.c_str(),
    };

    blaze_symbolize_cache_elf(symbolizer_, &cache);
  }

  if (cache_type == UserSymbolCacheType::per_pid) {
    for (int pid : util::get_pids_for_program(elf_file)) {
      blaze_cache_src_process cache = {
        .type_size = sizeof(cache),
        .pid = static_cast<uint32_t>(pid),
        .cache_vmas = true,
      };

      blaze_symbolize_cache_process(symbolizer_, &cache);
    }
  }
}

void Usyms::cache(const std::string &elf_file)
{
  if (config_.use_blazesym) {
    cache_blazesym(elf_file);
    return;
  }
  cache_bcc(elf_file);
}

std::string Usyms::resolve_bcc(uint64_t addr,
                               int32_t pid,
                               const std::string &pid_exe,
                               bool show_offset,
                               bool perf_mode)
{
  const auto cache_type = config_.user_symbol_cache_type;
  struct bcc_symbol usym;
  std::ostringstream symbol;
  void *psyms = nullptr;

  if (cache_type == UserSymbolCacheType::per_program) {
    if (!pid_exe.empty()) {
      // try to resolve symbol directly from program file
      // this might work when the process does not exist anymore, but cannot
      // resolve all symbols, e.g. those in a dynamically linked library
      std::map<uintptr_t, elf_symbol, std::greater<>> &symbol_table =
          symbol_table_cache_.contains(pid_exe)
              ? symbol_table_cache_[pid_exe]
              : (symbol_table_cache_[pid_exe] = util::get_symbol_table_for_elf(
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
        if (perf_mode)
          symbol << " (" << pid_exe << ")";
        return symbol.str();
      }
    }
    if (!exe_sym_.contains(pid_exe)) {
      // not cached, create new ProcSyms cache
      psyms = bcc_symcache_new(pid, &get_symbol_opts());
      exe_sym_[pid_exe] = std::make_pair(pid, psyms);
    } else {
      psyms = exe_sym_[pid_exe].second;
    }
  } else if (cache_type == UserSymbolCacheType::per_pid) {
    // cache user symbols per pid
    if (!pid_sym_.contains(pid)) {
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
    if (config_.cpp_demangle)
      symbol << usym.demangle_name;
    else
      symbol << usym.name;
    if (show_offset)
      symbol << "+" << usym.offset;
    if (perf_mode)
      symbol << " (" << usym.module << ")";
  } else {
    symbol << reinterpret_cast<void *>(addr);
    if (perf_mode)
      symbol << " ([unknown])";
  }

  if (cache_type == UserSymbolCacheType::none)
    bcc_free_symcache(psyms, pid);

  return symbol.str();
}

std::vector<std::string> Usyms::resolve_blazesym_impl(
    uint64_t addr,
    int32_t pid,
    const std::string &pid_exe,
    bool show_offset,
    bool perf_mode,
    bool show_debug_info)
{
  std::vector<std::string> str_syms;
  const blaze_sym *sym;

  if (symbolizer_ == nullptr) {
    symbolizer_ = create_symbolizer();
    if (symbolizer_ == nullptr)
      return str_syms;
  }

  auto cache_type = config_.user_symbol_cache_type;
  SCOPE_EXIT
  {
    if (cache_type == UserSymbolCacheType::none) {
      blaze_symbolizer_free(symbolizer_);
      symbolizer_ = nullptr;
    }
  };

  if (cache_type == UserSymbolCacheType::per_program) {
    if (!pid_exe.empty()) {
      blaze_symbolize_src_elf src = {
        .type_size = sizeof(src),
        .path = pid_exe.c_str(),
        .debug_syms = show_debug_info,
      };
      const blaze_syms *syms = blaze_symbolize_elf_virt_offsets(
          symbolizer_, &src, &addr, 1);
      if (syms == nullptr) {
        return str_syms;
      }

      SCOPE_EXIT
      {
        blaze_syms_free(syms);
      };

      sym = &syms->syms[0];

      add_symbols(sym, show_offset, perf_mode, str_syms);
    }
    return str_syms;
  }

  blaze_symbolize_src_process src = {
    .type_size = sizeof(src),
    .pid = static_cast<uint32_t>(pid),
    .debug_syms = show_debug_info,
    .perf_map = true,
  };

  const blaze_syms *syms = blaze_symbolize_process_abs_addrs(
      symbolizer_, &src, &addr, 1);
  if (syms == nullptr)
    return str_syms;
  SCOPE_EXIT
  {
    blaze_syms_free(syms);
  };

  sym = &syms->syms[0];
  add_symbols(sym, show_offset, perf_mode, str_syms);

  return str_syms;
}

std::vector<std::string> Usyms::resolve_blazesym(uint64_t addr,
                                                 int32_t pid,
                                                 const std::string &pid_exe,
                                                 bool show_offset,
                                                 bool perf_mode,
                                                 bool show_debug_info)
{
  auto syms = resolve_blazesym_impl(
      addr, pid, pid_exe, show_offset, perf_mode, show_debug_info);
  if (syms.empty()) {
    syms.push_back(stringify_addr(addr, perf_mode));
  }
  return syms;
}

std::vector<std::string> Usyms::resolve(uint64_t addr,
                                        int32_t pid,
                                        const std::string &pid_exe,
                                        bool show_offset,
                                        bool perf_mode,
                                        [[maybe_unused]] bool show_debug_info)
{
  if (config_.use_blazesym)
    return resolve_blazesym(
        addr, pid, pid_exe, show_offset, perf_mode, show_debug_info);
  return std::vector<std::string>{
    resolve_bcc(addr, pid, pid_exe, show_offset, perf_mode)
  };
}

struct bcc_symbol_option &Usyms::get_symbol_opts()
{
  static struct bcc_symbol_option symopts = {
    .use_debug_file = 1,
    .check_debug_file_crc = 1,
    .lazy_symbolize = config_.lazy_symbolication ? 1 : 0,
    .use_symbol_type = BCC_SYM_ALL_TYPES,
  };

  return symopts;
}

} // namespace bpftrace

#pragma GCC diagnostic pop
