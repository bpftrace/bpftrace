#pragma once

#include <format>
#include <string>

// This file/function is a hack to get around an internal Meta issue
// whereby bpftrace is built without support for some C++20 features e.g.
// std::format so we have this layer of indirection so this file can be replaced
// with the `fmt` version of format.
namespace bpftrace::util {

template <typename... T>
inline std::string format(std::format_string<T...> fmt, T &&...args)
{
  return std::format(fmt, std::forward<T &&>(args)...);
}

} // namespace bpftrace::util
