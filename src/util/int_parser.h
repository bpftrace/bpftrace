#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unistd.h>
#include <variant>

namespace bpftrace::util {

//   String -> int conversion specific to bpftrace
//
//   - error when trailing characters are found
//   - supports scientific notation, e.g. 1e6
//    - error when out of int range (1e20)
//    - error when base > 9 (12e3)
//   - support underscore as separator, e.g. 1_234_000
//
//   All errors are raised as std::invalid_argument exception
int64_t to_int(const std::string &num, int base);
uint64_t to_uint(const std::string &num, int base);

std::optional<std::variant<int64_t, uint64_t>> get_int_from_str(
    const std::string &s);

std::optional<pid_t> parse_pid(const std::string &str, std::string &err);

} // namespace bpftrace::util
