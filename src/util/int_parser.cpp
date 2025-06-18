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
  // The pair is the maximum value for the type, and the multiplier
  static std::map<std::string, std::pair<uint64_t, uint64_t>> int_config = {
    { "", { std::numeric_limits<uint64_t>::max(), 1 } },
    { "u", { std::numeric_limits<unsigned>::max(), 1 } },
    { "ul", { std::numeric_limits<unsigned long>::max(), 1 } },
    { "ull", { std::numeric_limits<unsigned long long>::max(), 1 } },
    { "l", { std::numeric_limits<long>::max(), 1 } },
    { "ll", { std::numeric_limits<long long>::max(), 1 } },
    { "ns", { std::numeric_limits<uint64_t>::max(), 1 } },
    { "us", { std::numeric_limits<uint64_t>::max(), 1000 } },
    { "ms", { std::numeric_limits<uint64_t>::max(), 1'000'000 } },
    { "s", { std::numeric_limits<uint64_t>::max(), 1'000'000'000 } },
    { "m", { std::numeric_limits<uint64_t>::max(), 60'000'000'000 } },
    { "h", { std::numeric_limits<uint64_t>::max(), 3'600'000'000'000 } },
    { "d", { std::numeric_limits<uint64_t>::max(), 86'400'000'000'000 } },
  };
  auto typespec = int_config.find(suffix);
  if (typespec == int_config.end()) {
    // Not a valid suffix.
    return make_error<NumberFormatError>("invalid trailing bytes", num);
  }

  // Is it out of the range? We consider this as an overflow.
  if (ret > (typespec->second.first / typespec->second.second)) {
    return make_error<OverflowError>(num, typespec->second.first);
  }
  return ret * typespec->second.second;
}

Result<int64_t> to_int(const std::string &num, int base)
{
  if (num.empty()) {
    return 0;
  }

  if (num[0] == '-') {
    auto int_val = to_uint(num.substr(1, num.size() - 1), base);
    if (!int_val) {
      return int_val;
    }
    // Converting without overflow.
    auto neg = -static_cast<int64_t>(*int_val - 1) - 1;
    if (neg > 0) {
      return make_error<OverflowError>(num,
                                       std::numeric_limits<int64_t>::max());
    }
    return neg;
  } else {
    auto int_val = to_uint(num);
    if (!int_val) {
      return int_val;
    }
    if (*int_val > std::numeric_limits<int64_t>::max()) {
      return make_error<OverflowError>(num,
                                       std::numeric_limits<int64_t>::max());
    }
    return *int_val;
  }
}

} // namespace bpftrace::util
