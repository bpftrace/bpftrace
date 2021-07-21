#include <algorithm>
#include <exception>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <type_traits>
#include <variant>

#include "int_parser.h"

namespace {

template <typename T>
T _parse_int(const std::string &num __attribute__((unused)),
             size_t *idx __attribute__((unused)),
             int base __attribute__((unused)))
{
  static_assert(not std::is_same_v<T, T>,
                "BUG: _parse_int not implemented for type");
}

template <>
int64_t _parse_int(const std::string &num, size_t *idx, int base)
{
  return std::stoll(num, idx, base);
}

template <>
uint64_t _parse_int(const std::string &num, size_t *idx, int base)
{
  return std::stoull(num, idx, base);
}

template <typename T>
std::variant<T, std::string> _parse_int(const std::string &num, int base)
{
  // https://en.cppreference.com/w/cpp/language/integer_literal#The_type_of_the_literal
  static auto int_size_re = std::regex("^(u|u?l?l)$", std::regex::icase);
  try
  {
    std::size_t idx;
    T ret = _parse_int<T>(num, &idx, base);

    if (idx != num.size())
    {
      auto trail = num.substr(idx, std::string::npos);
      auto match = std::regex_match(trail, int_size_re);

      if (!match)
        return "Found trailing non-numeric characters";
    }

    return ret;
  }
  catch (const std::exception &ex)
  {
    return ex.what();
  }
}

// integer variant of   10^exp
uint64_t _ten_pow(uint64_t exp)
{
  static const uint64_t v[] = { 1, 10, 100, 1000, 10000, 100000, 1000000 };
  if (exp > 6)
    return v[6] * _ten_pow(exp - 6);
  return v[exp];
}

// integer variant of scientific notation parsing
template <typename T>
std::variant<T, std::string> _parse_exp(const std::string &coeff,
                                        const std::string &exp)
{
  std::stringstream errmsg;
  auto maybe_coeff = _parse_int<T>(coeff, 10);
  if (auto err = std::get_if<std::string>(&maybe_coeff))
  {
    errmsg << "Coefficient part of scientific literal is not a valid number: "
           << coeff << ": " << err;
    return errmsg.str();
  }

  auto maybe_exp = _parse_int<T>(exp, 10);
  if (auto err = std::get_if<std::string>(&maybe_exp))
  {
    errmsg << "Exponent part of scientific literal is not a valid number: "
           << exp << ": " << err;
    return errmsg.str();
  }

  auto c = std::get<T>(maybe_coeff);
  auto e = std::get<T>(maybe_exp);

  if (c > 9)
  {
    errmsg << "Coefficient part of scientific literal must be in range (0,9), "
              "got: "
           << coeff;
    return errmsg.str();
  }

  if (e > 16)
  {
    errmsg << "Exponent will overflow integer range: " << exp;
    return errmsg.str();
  }

  return c * (T)_ten_pow(e);
}

} // namespace

namespace bpftrace {
namespace ast {
namespace int_parser {

template <typename T>
T to_int(const std::string &num, int base)
{
  std::string n(num);
  n.erase(std::remove(n.begin(), n.end(), '_'), n.end());

  std::variant<T, std::string> res;

  auto pos = n.find_first_of("eE");
  if (pos != std::string::npos)
  {
    res = _parse_exp<T>(n.substr(0, pos), n.substr(pos + 1, std::string::npos));
  }
  else
  {
    res = _parse_int<T>(n, base);
  }

  if (auto err = std::get_if<std::string>(&res))
    throw std::invalid_argument(*err);
  return std::get<T>(res);
}

int64_t to_int(const std::string &num, int base)
{
  return to_int<int64_t>(num, base);
}

uint64_t to_uint(const std::string &num, int base)
{
  return to_int<uint64_t>(num, base);
}

} // namespace int_parser
} // namespace ast
} // namespace bpftrace
