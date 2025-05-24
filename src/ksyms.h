#pragma once

#include <cstdint>
#include <optional>
#include <string>

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

  struct blaze_symbolizer *symbolizer_{ nullptr };

  std::vector<std::string> resolve_blazesym_impl(uint64_t addr,
                                                 bool show_offset,
                                                 bool perf_mode,
                                                 bool show_debug_info);
  std::vector<std::string> resolve_blazesym(uint64_t addr,
                                            bool show_offset,
                                            bool perf_mode,
                                            bool show_debug_info);

  std::string resolve_bcc(uint64_t addr, bool show_offset);
};
} // namespace bpftrace
