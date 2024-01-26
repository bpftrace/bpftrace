#pragma once

#include "bpfbytecode.h"
#include "mapmanager.h"

#include <cstdint>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

namespace bpftrace {

class BPFtrace;

class BpfProgram {
public:
  static std::optional<BpfProgram> CreateFromBytecode(
      const BpfBytecode &bytecode,
      const std::string &name,
      MapManager &maps);

  void assemble();

  const std::vector<uint8_t> &getCode();
  const std::vector<uint8_t> &getBTF();
  const std::vector<uint8_t> &getFuncInfos();

  BpfProgram(const BpfProgram &) = delete;
  BpfProgram &operator=(const BpfProgram &) = delete;
  BpfProgram(BpfProgram &&) = default;
  BpfProgram &operator=(BpfProgram &&) = delete;

private:
  explicit BpfProgram(const BpfBytecode &bytecode,
                      const std::string &name,
                      MapManager &bpftrace);

  void relocateInsns();
  void relocateFuncInfos();
  void appendFileFuncInfos(const struct btf_ext_info_sec *src,
                           size_t func_info_rec_size,
                           size_t insn_offset);

  const BpfBytecode &bytecode_;
  MapManager &maps_;
  std::string name_;
  std::vector<uint8_t> code_;
  // Offset in code_ where the .text begins (if .text was appended)
  size_t text_offset_ = 0;

  // Storage for kernel bpf_func_infos.
  // Note that ELF bpf_func_infos  store byte offsets from the section
  // start in insn_off, while the kernel expects _instruction_ offsets
  // from the beginning of the program code (i.e. what's in code_).
  std::vector<uint8_t> func_infos_;
};

} // namespace bpftrace
