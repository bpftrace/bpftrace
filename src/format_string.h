#pragma once

#include <ostream>
#include <regex>
#include <vector>

#include "printf.h"

namespace bpftrace {

/**
 * validate_fmt makes sure that the type are valid for the format specifiers
 */
std::string validate_format_string(const std::string &fmt,
                                   std::vector<Field> args);

struct Field;
/*
**
*/
class FormatString
{
private:
  /**
   * Split the format string on format specifiers, e.g.
   * 'foo %s bar' -> [ 'foo %s', 'bar' ]
   */
  void split();

public:
  /*
   * NOTE: As format strings are used as a vector of tuples the cereal
   * serialization can get hairy. Having a public constructor makes it easier.
   */
  FormatString() = default;

  FormatString(const char *s) : fmt_(s){};
  FormatString(std::string &s) : fmt_(s){};

  /**
   * format formats the format string with the given args. Its up to the caller
   * to ensure that the argument types match those of the call to validate_types
   */
  void format(std::ostream &out,
              std::vector<std::unique_ptr<IPrintable>> &args);

  /**
   * format_str is similar to format but returns a string instead of writing to
   * an ostream
   */
  std::string format_str(std::vector<std::unique_ptr<IPrintable>> &args);

  /**
   * length returns the length of the format string
   */
  inline size_t length() const noexcept
  {
    return fmt_.length();
  };
  inline size_t size() const noexcept
  {
    return length();
  };

  /**
   * str returns the format string as std::string
   */
  inline std::string str() const
  {
    return fmt_;
  };

  /**
   * c_str returns the format string as c string
   * */
  inline const char *c_str() const noexcept
  {
    return fmt_.c_str();
  };

private:
  std::string fmt_;
  std::vector<std::string> parts_;

  friend class cereal::access;

  template <typename Archive>
  void serialize(Archive &ar)
  {
    // NOTE: parts_ is not constructed until first use, so no point in
    // serializing it
    ar(fmt_);
  }
};

} // namespace bpftrace
