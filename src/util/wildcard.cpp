#include <algorithm>
#include <cstring>
#include <ranges>
#include <vector>

#include "util/strings.h"
#include "util/wildcard.h"

namespace bpftrace::util {

bool has_wildcard(const std::string &str)
{
  return str.find("*") != std::string::npos ||
         (str.find("[") != std::string::npos &&
          str.find("]") != std::string::npos);
}

// Splits input string by '*' delimiter and return the individual parts.
// Sets start_wildcard and end_wildcard if input starts or ends with '*'.
std::vector<std::string> get_wildcard_tokens(const std::string &input,
                                             bool &start_wildcard,
                                             bool &end_wildcard)
{
  if (input.empty())
    return {};

  start_wildcard = input[0] == '*';
  end_wildcard = input[input.length() - 1] == '*';

  std::vector<std::string> tokens = split_string(input, '*');
  auto it = std::ranges::remove(tokens, "");
  tokens.erase(it.begin(), it.end());
  return tokens;
}

bool wildcard_match(std::string_view str,
                    const std::vector<std::string> &tokens,
                    bool start_wildcard,
                    bool end_wildcard)
{
  size_t next = 0;

  if (!start_wildcard)
    if (str.find(tokens[0], next) != next)
      return false;

  for (const std::string &token : tokens) {
    size_t found = str.find(token, next);
    if (found == std::string::npos)
      return false;

    next = found + token.length();
  }

  if (!end_wildcard)
    if (str.length() != next)
      return false;

  return true;
}

} // namespace bpftrace::util
