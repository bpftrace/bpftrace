#include <cstring>
#include <functional>
#include <iomanip>

#include "util/opaque.h"

namespace bpftrace::util {

bool OpaqueValue::operator==(const OpaqueValue &other) const
{
  if (size() != other.size()) {
    return false;
  }
  return std::memcmp(data(), other.data(), size()) == 0;
}

bool OpaqueValue::operator!=(const OpaqueValue &other) const
{
  return !(*this == other);
}

bool OpaqueValue::operator<(const OpaqueValue &other) const
{
  size_t min_len = std::min(size(), other.size());
  int cmp = std::memcmp(data(), other.data(), min_len);
  if (cmp != 0) {
    return cmp < 0;
  }
  return size() < other.size();
}

size_t OpaqueValue::hash() const
{
  const char *backing_data = data();
  // We don't expect hashing to be common, but we do use the OpaqueValue as the
  // key for some map. We just use the simple djb2 algorithm, which should be
  // fine across a range of different data.
  size_t hash_value = 5381;
  for (size_t i = 0; i < size(); i++) {
    hash_value = ((hash_value << 5) + hash_value) +
                 static_cast<unsigned char>(backing_data[i]);
  }
  return hash_value;
}

std::ostream &operator<<(std::ostream &out, const OpaqueValue &value)
{
  const char *data = value.data();
  for (size_t i = 0; i < value.size(); i++) {
    out << std::hex << std::setfill('0') << std::setw(2)
        << static_cast<unsigned int>(static_cast<unsigned char>(data[i]));
  }
  return out;
}

} // namespace bpftrace::util
