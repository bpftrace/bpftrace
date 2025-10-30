#include <climits>
#include <cstdint>
#include <optional>

#include "integer_types.h"

namespace bpftrace::ast {

SizedType get_integer_type(uint64_t n)
{
  // Make the smallest possible sizedType based on n
  if (n <= std::numeric_limits<uint8_t>::max()) {
    return CreateUInt8();
  } else if (n <= std::numeric_limits<uint16_t>::max()) {
    return CreateUInt16();
  } else if (n <= std::numeric_limits<uint32_t>::max()) {
    return CreateUInt32();
  } else {
    return CreateUInt64();
  }
}

std::optional<SizedType> get_signed_integer_type(uint64_t n)
{
  if (n <= std::numeric_limits<int8_t>::max()) {
    return CreateInt8();
  } else if (n <= std::numeric_limits<int16_t>::max()) {
    return CreateInt16();
  } else if (n <= std::numeric_limits<int32_t>::max()) {
    return CreateInt32();
  } else if (n <= std::numeric_limits<int64_t>::max()) {
    return CreateInt64();
  } else {
    return std::nullopt;
  }
}

SizedType get_signed_integer_type(int64_t n)
{
  // Make the smallest possible sizedType based on n
  if (std::numeric_limits<int8_t>::min() <= n &&
      n <= std::numeric_limits<int8_t>::max()) {
    return CreateInt8();
  } else if (std::numeric_limits<int16_t>::min() <= n &&
             n <= std::numeric_limits<int16_t>::max()) {
    return CreateInt16();
  } else if (std::numeric_limits<int32_t>::min() <= n &&
             n <= std::numeric_limits<int32_t>::max()) {
    return CreateInt32();
  } else {
    return CreateInt64();
  }
}

} // namespace bpftrace::ast
