#pragma once

#include <cstdint>
#include <string>

namespace bpftrace {
class Config;

class Ksyms {
public:
  Ksyms(const Config &config);
  ~Ksyms();

  Ksyms(Ksyms &) = delete;
  Ksyms &operator=(const Ksyms &) = delete;

  std::string resolve(uint64_t addr, bool show_offset);

private:
  const Config &config_;
  void *ksyms_{ nullptr };
};
} // namespace bpftrace
