#include "bpfprogram.h"

#include "relocator.h"

#include <optional>
#include <stdexcept>
#include <tuple>

namespace bpftrace {

std::optional<BpfProgram> BpfProgram::CreateFromBytecode(
    const BpfBytecode &bytecode,
    const std::string &name,
    BPFtrace &bpftrace)
{
  if (bytecode.find(name) != bytecode.end())
  {
    return BpfProgram(bytecode, name, bpftrace);
  }
  return std::nullopt;
}

BpfProgram::BpfProgram(const BpfBytecode &bytecode,
                       const std::string &name,
                       BPFtrace &bpftrace)
    : bytecode_(bytecode), bpftrace_(bpftrace), name_(name), code_()
{
}

const std::vector<uint8_t> &BpfProgram::getCode()
{
  return code_;
}

void BpfProgram::assemble()
{
  if (!code_.empty())
    return;

  code_ = bytecode_.at(name_);

  // Perform relocations on the copy of the code for this particular program.
  auto relocator = Relocator(std::make_tuple(code_.data(), code_.size()),
                             bpftrace_);
  if (relocator.relocate())
    throw std::runtime_error("Could not relocate program, see log");
}

} // namespace bpftrace
