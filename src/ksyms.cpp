#include <bcc/bcc_syms.h>
#include <blazesym.h>
#include <sstream>

#include "ksyms.h"
#include "scopeguard.h"

namespace {
std::string stringify_addr(uint64_t addr)
{
  std::ostringstream symbol;
  symbol << reinterpret_cast<void *>(addr);
  return symbol.str();
}

std::string stringify_ksym(const char *name,
                           const blaze_symbolize_code_info *code_info,
                           uint64_t offset,
                           bool show_offset,
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
    if (is_inlined) {
      symbol << " (inlined)";
    }

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

} // namespace

namespace bpftrace {

Ksyms::Ksyms(const Config &config) : config_(config)
{
}

Ksyms::~Ksyms()
{
  if (ksyms_)
    bcc_free_symcache(ksyms_, -1);

  if (symbolizer_)
    blaze_symbolizer_free(symbolizer_);
}

std::string Ksyms::resolve_bcc(uint64_t addr, bool show_offset)
{
  struct bcc_symbol ksym;

  if (!ksyms_)
    ksyms_ = bcc_symcache_new(-1, nullptr);

  if (bcc_symcache_resolve(ksyms_, addr, &ksym) == 0) {
    std::ostringstream symbol;
    symbol << ksym.name;
    if (show_offset)
      symbol << "+" << ksym.offset;
    return symbol.str();
  }
  return stringify_addr(addr);
}

std::vector<std::string> Ksyms::resolve_blazesym_impl(uint64_t addr,
                                                      bool show_offset,
                                                      bool perf_mode,
                                                      bool show_debug_info)
{
  std::vector<std::string> str_syms;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
  if (symbolizer_ == nullptr) {
    blaze_symbolizer_opts opts = {
      .type_size = sizeof(opts),
      // Use the config here because the symbolizer is created once
      .code_info = config_.show_debug_info,
      .inlined_fns = config_.show_debug_info,
    };
    symbolizer_ = blaze_symbolizer_new_opts(&opts);
    if (symbolizer_ == nullptr)
      return str_syms;
  }

  blaze_symbolize_src_kernel src = {
    .type_size = sizeof(src),
    // Use default system-wide kallsyms file.
    .kallsyms = nullptr,
    // Disable discovery and usage of a vmlinux file.
    // TODO: We should eventually support that, incorporating discovery logic
    //       from find_vmlinux().
    .vmlinux = "",
    .debug_syms = show_debug_info,
  };
#pragma GCC diagnostic pop

  const blaze_syms *syms = blaze_symbolize_kernel_abs_addrs(
      symbolizer_, &src, &addr, 1);
  if (syms == nullptr)
    return str_syms;
  SCOPE_EXIT
  {
    blaze_syms_free(syms);
  };

  const blaze_sym *sym = &syms->syms[0];
  const struct blaze_symbolize_inlined_fn *inlined;

  if (sym == nullptr || sym->name == nullptr) {
    return str_syms;
  }

  // bpftrace prints stacks leaf first so the inlined functions
  // need to come first in the list (and in reverse order)
  for (int j = static_cast<int>(sym->inlined_cnt) - 1; j >= 0; j--) {
    inlined = &sym->inlined[j];
    if (inlined != nullptr) {
      str_syms.push_back(stringify_ksym(
          inlined->name, &inlined->code_info, 0, false, perf_mode, true));
    }
  }

  str_syms.push_back(stringify_ksym(
      sym->name, &sym->code_info, sym->offset, show_offset, perf_mode, false));

  return str_syms;
}

std::vector<std::string> Ksyms::resolve_blazesym(uint64_t addr,
                                                 bool show_offset,
                                                 bool perf_mode,
                                                 bool show_debug_info)
{
  auto syms = resolve_blazesym_impl(
      addr, show_offset, perf_mode, show_debug_info);
  if (syms.empty()) {
    syms.push_back(stringify_addr(addr));
  }

  return syms;
}

std::vector<std::string> Ksyms::resolve(uint64_t addr,
                                        bool show_offset,
                                        [[maybe_unused]] bool perf_mode,
                                        [[maybe_unused]] bool show_debug_info)
{
  if (config_.use_blazesym)
    return resolve_blazesym(addr, show_offset, perf_mode, show_debug_info);

  return std::vector<std::string>{ resolve_bcc(addr, show_offset) };
}

} // namespace bpftrace
