#include "struct.h"

namespace bpftrace {

bool Bitfield::operator==(const Bitfield &other) const {
  return read_bytes == other.read_bytes
    && mask == other.mask
    && access_rshift == other.access_rshift;
}

bool Bitfield::operator!=(const Bitfield &other) const {
  return !(*this == other);
}

} // namespace bpftrace
