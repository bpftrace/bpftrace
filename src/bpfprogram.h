#pragma once

#include "bpffeature.h"
#include "btf.h"
#include "types.h"

#include <bpf/libbpf.h>
#include <cstdint>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

namespace bpftrace {

class BpfBytecode;
class BPFtrace;

// This class abstracts a single BPF program by encapsulating libbpf's
// 'struct bpf_prog'. Currently, it also performs relocations of BPF bytecode
// which will go away once we move to libbpf-based loading.
class BpfProgram {
public:
  explicit BpfProgram(struct bpf_program *bpf_prog);

  void assemble(const BpfBytecode &bytecode);
  void load(const Probe &probe,
            const BpfBytecode &bytecode,
            const BTF &btf,
            BPFfeature &feature);

  int fd() const;

  BpfProgram(const BpfProgram &) = delete;
  BpfProgram &operator=(const BpfProgram &) = delete;
  BpfProgram(BpfProgram &&) = default;
  BpfProgram &operator=(BpfProgram &&) = delete;

private:
  const std::vector<uint8_t> &getCode() const;
  const std::vector<uint8_t> &getFuncInfos() const;

  void relocateInsns(const BpfBytecode &bytecode);
  void relocateSection(const std::string &relsecname,
                       bpf_insn *,
                       const BpfBytecode &bytecode);
  void relocateFuncInfos(const BpfBytecode &bytecode);
  void appendFileFuncInfos(const struct btf_ext_info_sec *src,
                           size_t func_info_rec_size,
                           size_t insn_offset);

  struct bpf_program *bpf_prog_;
  int fd_ = -1;

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
