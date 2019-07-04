#include "disasm.h"

namespace bpftrace {

class DummyDisasm : public IDisasm
{
  AlignState is_aligned(uint64_t offset __attribute__((unused)),
                        uint64_t pc __attribute__((unused))) override
  {
    return AlignState::NotSupp;
  }
};

Disasm::Disasm(std::string &path __attribute__((unused)))
{
  dasm_ = std::make_unique<DummyDisasm>();
}

} // namespace bpftrace
