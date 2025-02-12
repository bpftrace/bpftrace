#include <sstream>

#include <bcc/bcc_syms.h>
#ifdef HAVE_BLAZESYM
#include <blazesym.h>
#endif

#include "config.h"
#include "ksyms.h"
#include "scopeguard.h"
#include "utils.h"

namespace {
std::string stringify_addr(uint64_t addr)
{
  std::ostringstream symbol;
  symbol << reinterpret_cast<void *>(addr);
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

#ifdef HAVE_BLAZESYM
  if (symbolizer_)
    blaze_symbolizer_free(symbolizer_);
#endif
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

#ifdef HAVE_BLAZESYM
std::optional<std::string> Ksyms::resolve_blazesym_int(uint64_t addr,
                                                       bool show_offset)
{
  if (symbolizer_ == nullptr) {
    symbolizer_ = blaze_symbolizer_new();
    if (symbolizer_ == nullptr)
      return std::nullopt;
  }

  std::ostringstream symbol;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
  blaze_symbolize_src_kernel src = {
    .type_size = sizeof(src),
    // Use default system-wide kallsyms file.
    .kallsyms = nullptr,
    // Disable discovery and usage of a vmlinux file.
    // TODO: We should eventually support that, incorporating discovery logic
    //       from find_vmlinux().
    .vmlinux = "",
  };
#pragma GCC diagnostic pop
  uint64_t addrs[1] = { addr };

  const blaze_syms *syms = blaze_symbolize_kernel_abs_addrs(
      symbolizer_, &src, addrs, ARRAY_SIZE(addrs));
  if (syms == nullptr)
    return std::nullopt;
  SCOPE_EXIT
  {
    blaze_syms_free(syms);
  };

  const blaze_sym *sym = &syms->syms[0];
  if (sym->name == nullptr) {
    return std::nullopt;
  }

  symbol << sym->name;
  if (show_offset) {
    auto offset = addr - sym->addr;
    symbol << "+" << offset;
  }
  return symbol.str();
}

std::string Ksyms::resolve_blazesym(uint64_t addr, bool show_offset)
{
  if (auto sym = resolve_blazesym_int(addr, show_offset)) {
    return *sym;
  }
  return stringify_addr(addr);
}
#endif

std::string Ksyms::resolve(uint64_t addr, bool show_offset)
{
#ifdef HAVE_BLAZESYM
  if (config_.get(ConfigKeyBool::use_blazesym))
    return resolve_blazesym(addr, show_offset);
#endif
  return resolve_bcc(addr, show_offset);
}
} // namespace bpftrace
