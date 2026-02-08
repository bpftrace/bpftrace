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

namespace bpftrace {

void RequiredResources::save_state(std::ostream &out) const
{
  for (const auto &[name, info] : maps_info) {
    if (info.key_type.IsTupleTy()) {
        auto struct_ptr = info.key_type.GetStruct();
        auto locked = struct_ptr.lock();
    }
  }

  cereal::BinaryOutputArchive archive(out);
  archive(*this);
}

void RequiredResources::load_state(std::istream &in)
{
  cereal::BinaryInputArchive archive(in);
  archive(*this);
}

class Membuf : public std::streambuf {
public:
  Membuf(uint8_t *begin, uint8_t *end)
  {
    auto *b = reinterpret_cast<char *>(begin);
    auto *e = reinterpret_cast<char *>(end);
    this->setg(b, b, e);
  }
};

void RequiredResources::load_state(const uint8_t *ptr, size_t len)
{
  auto *addr = const_cast<uint8_t *>(ptr);
  Membuf mbuf(addr, addr + len);
  std::istream istream(&mbuf);
  cereal::BinaryInputArchive archive(istream);
  archive(*this);

  // Immediately after archive, collect all Struct pointers while cereal
  // still has them as valid shared_ptrs
  for (const auto &[name, info] : maps_info) {
    if (info.key_type.IsTupleTy() || info.key_type.IsRecordTy()) {
      auto ptr = info.key_type.GetStruct().lock();
      if (ptr) {
        struct_storage_.push_back(std::const_pointer_cast<Struct>(ptr));
      }
    }

    if (info.value_type.IsTupleTy() || info.value_type.IsRecordTy()) {
      auto ptr = info.value_type.GetStruct().lock();
      if (ptr) {
        struct_storage_.push_back(std::const_pointer_cast<Struct>(ptr));
      }
    }
  }
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
