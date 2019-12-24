#pragma once

#include <map>
#include "types.h"

namespace bpftrace {

struct Bitfield {
  bool operator==(const Bitfield &other) const;
  bool operator!=(const Bitfield &other) const;

  // Read `read_bytes` bytes starting from this field's offset
  size_t read_bytes;
  // Then rshift the resulting value by `access_rshift` to get field value
  size_t access_rshift;
  // Then logical AND `mask` to mask out everything but this bitfield
  size_t mask;
};

struct Field {
  SizedType type;
  int offset;

  bool is_bitfield;
  Bitfield bitfield;
};

using FieldsMap = std::map<std::string, Field>;

struct Struct
{
  int size;
  FieldsMap fields;
};

} // namespace bpftrace
