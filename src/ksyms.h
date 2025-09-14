#pragma once

#include <cstdint>
#include <optional>
#include <string>

#ifdef HAVE_BLAZESYM
#include <blazesym.h>
#endif

#include "config.h"

namespace bpftrace {
class Config;

class Ksyms {
public:
  Ksyms(const Config &config);
  ~Ksyms();
  Ksyms(Ksyms &) = delete;
  Ksyms &operator=(const Ksyms &) = delete;

  std::vector<std::string> resolve(uint64_t addr,
                                   bool show_offset,
                                   bool perf_mode,
                                   bool show_debug_info);

private:
  const Config &config_;
  void *ksyms_{ nullptr };

#ifdef HAVE_BLAZESYM
  blaze_symbolizer *symbolizer_{ nullptr };

  std::vector<std::string> resolve_blazesym_impl(uint64_t addr,
                                                 bool show_offset,
                                                 bool perf_mode,
                                                 bool show_debug_info);
  std::vector<std::string> resolve_blazesym(uint64_t addr,
                                            bool show_offset,
                                            bool perf_mode,
                                            bool show_debug_info);
#endif

  std::string resolve_bcc(uint64_t addr, bool show_offset);
};
} // namespace bpftrace
