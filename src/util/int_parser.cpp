#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <ranges>

#include "util/int_parser.h"
#include "util/result.h"

namespace bpftrace::util {

char OverflowError::ID;
void OverflowError::log(llvm::raw_ostream &OS) const
{
  OS << "overflow error, maximum value is " << max_ << ": " << num_;
}

char NumberFormatError::ID;
void NumberFormatError::log(llvm::raw_ostream &OS) const
{
  OS << msg_ << ": " << num_;
}

static std::optional<uint64_t> safe_exp(uint64_t base, uint64_t exp)
{
  constexpr uint64_t max_factor = std::numeric_limits<uint64_t>::max() / 10;
  uint64_t result = base;
  while (exp > 0) {
    if (result > max_factor) {
      return std::nullopt;
    }
    result = result * 10;
    exp--;
  }
  return result;
}

Result<uint64_t> to_uint(const std::string &num, int base)
{
  std::string n(num); // Copy.

  // Drop all underscores, a convenience separator.
  auto underscores = std::ranges::remove(n, '_');
  n.erase(underscores.begin(), underscores.end());

  // Discover the base, if needed.
  if (base == 0 && n.size() >= 2) {
    if (n.starts_with("0x") || n.starts_with("0X")) {
      return to_uint(n.substr(2, n.size() - 2), 16);
    } else if (n.starts_with("0b") || n.starts_with("0B")) {
      return to_uint(n.substr(2, n.size() - 2), 2);
    } else if (n.starts_with("0") && n[1] >= '0' && n[1] <= '7') {
      return to_uint(n.substr(1, n.size() - 1), 8);
    }
  }

  // Parse the integer.
  //
  // Note that we need to use reset `errno` in order to reliably
  // detect an integer too large. This will be set to ERANGE and
  // the maximum value will be returned, but if we successfully
  // parse this value, we need to ensure that `errno` is cleared
  // to distinguish it from a real error.
  char *endptr = nullptr;
  errno = 0;
  uint64_t ret = std::strtoull(n.c_str(), &endptr, base);
  if (ret == 0 && endptr == n.c_str()) {
    return make_error<NumberFormatError>("invalid integer", num);
  }
  if (ret == ULLONG_MAX && errno == ERANGE) {
    return make_error<OverflowError>(num, ULLONG_MAX);
  }

  // Check for a valid end pointer. If we have an exponent, then should must
  // parse the remainder of the string in base 10.
  if ((*endptr == 'e' || *endptr == 'E') && *(endptr + 1) >= '1' &&
      *(endptr + 1) <= '9') {
    if (ret <= 0 || ret >= 10) {
      return make_error<NumberFormatError>(
          "coefficient part of scientific literal must be 1-9", num);
    }
    char *exp = endptr + 1;
    uint64_t exp_pow = std::strtoull(exp, &endptr, 10);
    if (exp_pow == 0 && endptr == exp) {
      return make_error<NumberFormatError>("invalid exponent", num);
    }
    // Compute the result, ensuring that we never overflow.
    auto maybe_result = safe_exp(ret, exp_pow);
    if (!maybe_result) {
      return make_error<OverflowError>(num,
                                       std::numeric_limits<uint64_t>::max());
    }
    ret = maybe_result.value();
  }

  // Check to see if this has been bound to a specific type. Note that we
  // treat no suffix as a 64-bit integer type.
  // https://en.cppreference.com/w/cpp/language/integer_literal#The_type_of_the_literal
  std::string suffix(endptr);
  static std::map<std::string, uint64_t> max = {
    { "", std::numeric_limits<uint64_t>::max() },
    { "u", std::numeric_limits<unsigned>::max() },
    { "ul", std::numeric_limits<unsigned long>::max() },
    { "ull", std::numeric_limits<unsigned long long>::max() },
    { "l", std::numeric_limits<long>::max() },
    { "ll", std::numeric_limits<long long>::max() },
  };
  auto typespec = max.find(suffix);
  if (typespec == max.end()) {
    // Not a valid suffix.
    return make_error<NumberFormatError>("invalid trailing bytes", num);
  }
  // Is it out of the range? We consider this as an overflow.
  if (ret > typespec->second) {
    return make_error<OverflowError>(num, typespec->second);
  }
  return ret;
}

} // namespace bpftrace::util
