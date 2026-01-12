#pragma once

#include <ostream>
#include <regex>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "types.h"

namespace bpftrace {

class FormatError : public ErrorInfo<FormatError> {
public:
  FormatError(std::string msg) : msg_(std::move(msg)) {};
  static char ID;
  void log(llvm::raw_ostream &OS) const override;

private:
  std::string msg_;
};

namespace output {
struct Primitive;
} // namespace output

// FormatSpec is a parsed format token.
class FormatSpec {
public:
  bool left_align = false;     // -
  bool show_sign = false;      // +
  bool space_prefix = false;   // (space)
  bool alternate_form = false; // #
  bool lead_zeros = false;     // 0
  int width = 0;               // field width
  int precision = -1;          // precision after decimal point
  std::string length_modifier; // h, l, ll, etc.
  std::string specifier;       // d, s, x, etc.
private:
  static const std::regex regex;
  FormatSpec(const std::smatch &match);
  Result<std::string> apply(const output::Primitive &p) const;
  friend class FormatString;
};

class FormatString {
public:
  FormatString();
  FormatString(std::string fmt);
  ~FormatString();

  // check can be used to check if the format is valid, given a set of arguments
  // passed in. This does a best effort analysis based on the types.
  Result<> check(const std::vector<SizedType> &args) const;

  // format formats the format string with the given args. Its up to the
  // caller to ensure that the argument types match those of the call to
  // validate_types.
  std::string format(const std::vector<output::Primitive> &args) const;

  // returns the original format string.
  const std::string &str() const
  {
    return fmt_;
  }

  // These may be used by callers to do manual validation. The fragments must be
  // exactly one element larger than the specs, and the sequence that is
  // constructed is: (fragment, spec, fragment, ..., spec, fragment).
  std::vector<std::string> fragments;
  std::vector<FormatSpec> specs;

private:
  std::string fmt_;

  // parses the internal format string.
  void parse();

  friend class cereal::access;

  template <typename Archive>
  void serialize(Archive &ar)
  {
    ar(fmt_);
    if (fragments.empty() && specs.empty()) {
      parse();
    }
  }
};

} // namespace bpftrace
