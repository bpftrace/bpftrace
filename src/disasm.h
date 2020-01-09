#pragma once

#include <memory>
#include <string>

namespace bpftrace {

enum class AlignState
{
  Ok,
  Fail,
  NotAlign,
  NotSupp
};

class IDisasm
{
public:
  virtual AlignState is_aligned(uint64_t offset, uint64_t pc) = 0;
};

class Disasm
{
public:
  Disasm(std::string &path);

  AlignState is_aligned(uint64_t offset, uint64_t pc)
  {
    return dasm_->is_aligned(offset, pc);
  }

private:
  std::unique_ptr<IDisasm> dasm_;
};

} // namespace bpftrace
