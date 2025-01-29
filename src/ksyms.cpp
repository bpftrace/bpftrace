#include <sstream>

#include <bcc/bcc_syms.h>

#include "ksyms.h"

namespace bpftrace {
Ksyms::Ksyms(const Config &config) : config_(config)
{
}

std::string Ksyms::resolve(uint64_t addr, bool show_offset)
{
  struct bcc_symbol ksym;
  std::ostringstream symbol;

  if (!ksyms_)
    ksyms_ = bcc_symcache_new(-1, nullptr);

  if (bcc_symcache_resolve(ksyms_, addr, &ksym) == 0) {
    symbol << ksym.name;
    if (show_offset)
      symbol << "+" << ksym.offset;
  } else {
    symbol << reinterpret_cast<void *>(addr);
  }

  return symbol.str();
}

Ksyms::~Ksyms()
{
  if (ksyms_)
    bcc_free_symcache(ksyms_, -1);
}
} // namespace bpftrace
