#pragma once

#include <optional>

#include "types.h"

namespace bpftrace::ast {

SizedType get_integer_type(uint64_t n);
std::optional<SizedType> get_signed_integer_type(uint64_t n);
SizedType get_signed_integer_type(int64_t n);
std::optional<SizedType> sized_type_from_c_type(const std::string& ident);

} // namespace bpftrace::ast
