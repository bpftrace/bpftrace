#include <climits>
#include <cstdint>
#include <optional>

#include "integer_types.h"

namespace bpftrace::ast {

SizedType get_integer_type(uint64_t n)
{
  // Make the smallest possible signed sizedType based on n
  // or an unsigned SizedType if it exceeds the largest int64
  SizedType ty;
  if (n <= std::numeric_limits<int8_t>::max()) {
    ty = CreateInt8();
  } else if (n <= std::numeric_limits<int16_t>::max()) {
    ty = CreateInt16();
  } else if (n <= std::numeric_limits<int32_t>::max()) {
    ty = CreateInt32();
  } else if (n <= std::numeric_limits<int64_t>::max()) {
    ty = CreateInt64();
  } else {
    return CreateUInt64();
  }
  // Non-negative literals that fit in a signed type can be treated as
  // either signed or unsigned. Values exceeding INT64_MAX require
  // unsigned representation and are not flexible.
  ty.SetSignFlexible(true);
  return ty;
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
