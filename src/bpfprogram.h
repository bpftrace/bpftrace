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

  const BpfBytecode &bytecode_;
  BPFtrace &bpftrace_;
  std::string name_;
  std::vector<uint8_t> code_;
  // Offset in code_ where the .text begins (if .text was appended)
  size_t text_offset_;
};

} // namespace bpftrace
