#include "bpftrace.h"
#include <cstdint>
#include <optional>
#include <string>
#include <tuple>

namespace bpftrace {

class BpfProgram
{
public:
  static std::optional<BpfProgram> CreateFromBytecode(
      const BpfBytecode &bytecode,
      const char *name,
      BPFtrace &bpftrace);

  std::tuple<uint8_t *, uintptr_t> getCode();
  BpfProgram(BpfProgram const &) = default;
  BpfProgram(BpfProgram &&) = default;

private:
  explicit BpfProgram(const BpfBytecode &bytecode,
                      const char *name,
                      BPFtrace &bpftrace);

  void assemble();
  void relocateInsns();
  void relocateMaps();
  void relocateFuncInfos();
  void appendFileFuncInfos(const struct btf_ext_info_sec *src,
                           size_t func_info_rec_size,
                           size_t insn_offset);

  const BpfBytecode &bytecode_;
  BPFtrace &bpftrace_;
  std::string name_;
  std::vector<uint8_t> code_;
  // Offset in code_ where the .text begins (if .text was appended)
  size_t text_offset_;

  // Storage for kernel bpf_func_infos.
  // Note that ELF bpf_func_infos  store byte offsets from the section
  // start in insn_off, while the kernel expects _instruction_ offsets
  // from the beginning of the program code (i.e. what's in code_).
  std::vector<uint8_t> func_infos_;
};

} // namespace bpftrace
