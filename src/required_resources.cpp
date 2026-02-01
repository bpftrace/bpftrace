#include <cereal/archives/binary.hpp>
#include <cereal/types/map.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/optional.hpp>
#include <cereal/types/set.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/tuple.hpp>
#include <cereal/types/unordered_set.hpp>
#include <cereal/types/vector.hpp>

#include "required_resources.h"
#include "util/io.h"

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
  auto *addr = const_cast<uint8_t *>(ptr);
  util::Membuf mbuf(addr, addr + len);
  std::istream istream(&mbuf);
  cereal::BinaryInputArchive archive(istream);
  archive(*this);
}

std::ostream &operator<<(std::ostream &os, const RuntimeErrorInfo &info)
{
  switch (info.error_id) {
    case RuntimeErrorId::HELPER_ERROR: {
      // Helper errors are handled separately in output.
      os << "";
      break;
    }
    case RuntimeErrorId::DIVIDE_BY_ZERO: {
      os << DIVIDE_BY_ZERO_MSG;
      break;
    }
    case RuntimeErrorId::ARRAY_ACCESS_OOB: {
      os << ARRAY_ACCESS_OOB_MSG;
      break;
    }
    case RuntimeErrorId::CPU_COUNT_MISMATCH: {
      os << CPU_COUNT_MISMATCH_MSG;
      break;
    }
    case RuntimeErrorId::KSTACK: {
      os << KSTACK_MSG;
      break;
    }
    case RuntimeErrorId::USTACK: {
      os << USTACK_MSG;
      break;
    }
  }
  return os;
}

} // namespace bpftrace
