#pragma once

#include <string>
#include <string_view>

namespace bpftrace::util {

// Compute whether two strings are similar enough by some arbitrary
// 'similarity' score. This is not well-defined or guaranteed to meet any
// standard, but is guaranteed to not be unreasonably slow for relatively
// short, user-provided strings.
static bool is_similar(const std::string &user_str,
                       const std::string &target_str)
{
  // We could make this arbitrarily complex, but the strings here are quite
  // small. What we do is try to find the largest common substring.
  size_t common = 0;
  std::string_view needle(user_str);
  for (int i = 0, j = 1; static_cast<size_t>(j) <= user_str.size();) {
    std::string_view v = needle.substr(i, j - i);
    if (target_str.find(v) != std::string::npos) {
      common = j - i;
      j++;
    } else {
      i++;
    }
  }
  // If the largest common substring is greater than 1/2 of the characters of
  // the shortest string (round down, to allow for a typo in the middle), then
  // we consider this to be the same.
  size_t sz = std::min(user_str.size(), target_str.size());
  return common > 1 && common >= sz / 2;
}

} // namespace bpftrace::util
