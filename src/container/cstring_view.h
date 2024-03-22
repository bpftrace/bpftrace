#pragma once

#include <string>
#include <string_view>

namespace bpftrace {

/*
 * cstring_view
 *
 * A restricted version of std::string_view which guarantees that the underlying
 * string buffer will be null-terminated. This can be useful when interacting
 * with C APIs while avoiding the use of char* and unnecessary copies from using
 * std::string.
 *
 * We only allow constructing cstring_view from types which are guaranteed to
 * store null-terminated strings. All modifiers or operations on cstring_view
 * will also maintain the null-terminated property.
 */
class cstring_view : public std::string_view {
public:
  constexpr cstring_view(const char *str) noexcept : std::string_view{ str }
  {
  }
  // This ctor can be made constexpt in C++20:
  cstring_view(const std::string &str) noexcept : std::string_view{ str }
  {
  }

  constexpr const char *c_str() const noexcept
  {
    return data();
  }

private:
  // Disallow use of functions which can break the null-termination invariant
  using std::string_view::copy;
  using std::string_view::remove_suffix;
  using std::string_view::substr;
};

} // namespace bpftrace
