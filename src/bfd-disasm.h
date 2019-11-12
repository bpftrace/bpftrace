#pragma once

#include "disasm.h"

namespace bpftrace {

class BfdDisasm : public IDisasm
{
public:
  BfdDisasm(std::string &path);
  ~BfdDisasm();

  AlignState is_aligned(uint64_t offset, uint64_t pc);

private:
  int fd_ = -1;
  uint64_t size_;
};

} // namespace bpftrace
