#include "bpfbytecode.h"

#include <stdexcept>

namespace bpftrace {

void BpfBytecode::addSection(const std::string &name,
                             std::vector<uint8_t> &&data)
{
  sections_.emplace(name, data);
}

bool BpfBytecode::hasSection(const std::string &name) const
{
  return sections_.find(name) != sections_.end();
}

const std::vector<uint8_t> &BpfBytecode::getSection(
    const std::string &name) const
{
  if (!hasSection(name))
  {
    throw std::runtime_error("Bytecode is missing section " + name);
  }
  return sections_.at(name);
}

} // namespace bpftrace
