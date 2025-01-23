#pragma once

#include <cstdint>
#include <string>

class Ksyms {
public:
  Ksyms() = default;
  ~Ksyms();

  Ksyms(Ksyms &) = delete;
  Ksyms &operator=(const Ksyms &) = delete;

  std::string resolve(uint64_t addr, bool show_offset);

private:
  void *ksyms_{ nullptr };
};
