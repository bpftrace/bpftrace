#pragma once

#include "mapmanager.h"

#include <cstdint>
#include <optional>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

namespace bpftrace {

using BpfBytecode = std::unordered_map<std::string, std::vector<uint8_t>>;

class BPFtrace;

class BpfProgram
{
public:
  static std::optional<BpfProgram> CreateFromBytecode(
      const BpfBytecode &bytecode,
      const std::string &name,
      MapManager &maps);

  void assemble();

  const std::vector<uint8_t> &getCode();
  const std::vector<uint8_t> &getBTF();

  BpfProgram(const BpfProgram &) = delete;
  BpfProgram &operator=(const BpfProgram &) = delete;
  BpfProgram(BpfProgram &&) = default;
  BpfProgram &operator=(BpfProgram &&) = delete;

private:
  explicit BpfProgram(const BpfBytecode &bytecode,
                      const std::string &name,
                      MapManager &bpftrace);

  void relocateInsns();
  void relocateMaps();

  const BpfBytecode &bytecode_;
  MapManager &maps_;
  std::string name_;
  std::vector<uint8_t> code_;
  // Offset in code_ where the .text begins (if .text was appended)
  size_t text_offset_ = 0;
};

} // namespace bpftrace
