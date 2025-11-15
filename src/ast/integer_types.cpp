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

static std::map<std::string, SizedType> C_INT_TYPES = {
  { "char", CreateInt8() },       { "int8_t", CreateInt8() },
  { "uint8_t", CreateUInt8() },   { "short", CreateInt16() },
  { "int16_t", CreateInt16() },   { "uint16_t", CreateUInt16() },
  { "int", CreateInt32() },       { "int32_t", CreateInt32() },
  { "uint32_t", CreateUInt32() }, { "int64_t", CreateInt64() },
  { "uint64_t", CreateUInt64() },
};

std::optional<SizedType> sized_type_from_c_type(const std::string& ident)
{
  if (ident == "size_t" || ident == "uintptr_t") {
    return sizeof(long) == 4 ? CreateUInt32() : CreateUInt64();
  } else if (ident == "long" || ident == "intptr_t") {
    return sizeof(long) == 4 ? CreateInt32() : CreateInt64();
  } else {
    auto found = C_INT_TYPES.find(ident);
    if (found != C_INT_TYPES.end()) {
      return found->second;
    }
  }

  return std::nullopt;
}

} // namespace bpftrace::ast
