#include "bpfprogram.h"
#include "relocator.h"
#include <optional>
#include <stdexcept>
#include <tuple>

namespace bpftrace {

std::optional<BpfProgram> BpfProgram::CreateFromBytecode(BpfBytecode &bytecode,
                                                         const char *name,
                                                         BPFtrace &bpftrace)
{
  if (bytecode.find(name) != bytecode.end())
  {
    return BpfProgram(bytecode, name, bpftrace);
  }
  return std::nullopt;
}

BpfProgram::BpfProgram(BpfBytecode &bytecode,
                       const char *name,
                       BPFtrace &bpftrace)
    : bytecode_(bytecode), bpftrace_(bpftrace), name_(name), code_()
{
}

std::tuple<uint8_t *, uintptr_t> BpfProgram::getCode()
{
  if (code_.empty())
  {
    assemble();
  }
  return std::make_tuple(code_.data(), (uintptr_t)code_.size());
}

void BpfProgram::assemble()
{
  if (!code_.empty())
    return;

  auto &section = bytecode_.at(name_);
  code_.reserve(section.size());
  code_.assign(section.data(), section.data() + section.size());

  // Perform relocations on the copy of the code for this particular program.
  auto relocator = Relocator(std::make_tuple(code_.data(), code_.size()),
                             bpftrace_);
  if (relocator.relocate())
    throw std::runtime_error("Could not relocate program, see log");
}

} // namespace bpftrace
