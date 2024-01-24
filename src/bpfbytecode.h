#pragma once

#include "bpffeature.h"
#include <cereal/access.hpp>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace bpftrace {

using SectionMap = std::unordered_map<std::string, std::vector<uint8_t>>;

class BpfBytecode
{
public:
  BpfBytecode()
  {
  }

  BpfBytecode(const BpfBytecode &) = delete;
  BpfBytecode &operator=(const BpfBytecode &) = delete;
  BpfBytecode(BpfBytecode &&) = default;
  BpfBytecode &operator=(BpfBytecode &&) = default;

  void addSection(const std::string &name, std::vector<uint8_t> &&data);
  bool hasSection(const std::string &name) const;
  const std::vector<uint8_t> &getSection(const std::string &name) const;

  void fixupBTF(BPFfeature &feature);

private:
  SectionMap sections_;

  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(sections_);
  }
};

} // namespace bpftrace
