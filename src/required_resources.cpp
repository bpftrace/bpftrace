#include "required_resources.h"

#include <cereal/archives/binary.hpp>
#include <cereal/types/map.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/optional.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/tuple.hpp>
#include <cereal/types/unordered_set.hpp>
#include <cereal/types/vector.hpp>

#include "bpftrace.h"
#include "log.h"
#include "utils.h"

namespace bpftrace {

void RequiredResources::save_state(std::ostream &out) const
{
  cereal::BinaryOutputArchive archive(out);
  archive(*this);
}

void RequiredResources::load_state(std::istream &in)
{
  cereal::BinaryInputArchive archive(in);
  archive(*this);
}

void RequiredResources::load_state(const uint8_t *ptr, size_t len)
{
  auto addr = const_cast<uint8_t *>(ptr);
  Membuf mbuf(addr, addr + len);
  std::istream istream(&mbuf);
  cereal::BinaryInputArchive archive(istream);
  archive(*this);
}

} // namespace bpftrace
