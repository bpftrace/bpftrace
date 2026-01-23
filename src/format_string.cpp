#include <cstring>
#include <iomanip>

#include "format_string.h"
#include "output/output.h"
#include "struct.h"
#include "util/exceptions.h"
#include "util/strings.h"

namespace bpftrace {

using namespace output;

char FormatError::ID;

void FormatError::log(llvm::raw_ostream& OS) const
{
  OS << msg_;
}

// N.B. the `r`, `rh` and `rx` specifiers are non-standard and also have
// modifiers that *follow* the primary specifier. This means that they need
// special cases, and the ordering matters to ensure that we capture the
// modifiers if they are present (so `r` is the final match in the list).
const std::regex FormatSpec::regex(
    R"(%(-?)(\+?)( ?)(#?)(0?)(\*|\d+)?(?:\.(\*|\d+))?([hlLjzt]*)([diouxXeEfFgGaAcspn%]|rh|rx|r))");

FormatSpec::FormatSpec(const std::smatch& match)
{
  left_align = !match[1].str().empty();
  show_sign = !match[2].str().empty();
  space_prefix = !match[3].str().empty();
  alternate_form = !match[4].str().empty();
  lead_zeros = !match[5].str().empty();
  if (!match[6].str().empty() && match[6].str() != "*") {
    width = std::stoi(match[6].str());
  }
  if (!match[7].str().empty() && match[7].str() != "*") {
    precision = std::stoi(match[7].str());
  }
  length_modifier = match[8].str();
  specifier = match[9].str();
}

FormatString::FormatString() = default;

FormatString::FormatString(std::string fmt) : fmt_(std::move(fmt))
{
  parse();
}

FormatString::~FormatString() = default;

void FormatString::parse()
{
  fragments.clear();
  specs.clear();

  auto begin = std::sregex_iterator(fmt_.begin(),
                                    fmt_.end(),
                                    FormatSpec::regex);
  auto end = std::sregex_iterator();

  size_t last_match_end = 0;
  std::stringstream last_fragment;
  for (auto it = begin; it != end; ++it) {
    last_fragment << fmt_.substr(last_match_end,
                                 it->position() - last_match_end);
    last_match_end = it->position() + it->length();
    auto spec = FormatSpec(*it);
    if (spec.specifier == "%") {
      last_fragment << "%";
      continue;
    }
    fragments.emplace_back(last_fragment.str());
    last_fragment.str(""); // Reset the fragment.
    specs.emplace_back(std::move(spec));
  }
  last_fragment << fmt_.substr(last_match_end);
  fragments.emplace_back(last_fragment.str());
}

Result<> FormatString::check(const std::vector<SizedType>& args) const
{
  std::stringstream err;
  if (args.size() < specs.size()) {
    err << "not enough arguments for format string (" << args.size()
        << " supplied, " << specs.size() << " expected)";
    return make_error<FormatError>(err.str());
  }
  if (args.size() > specs.size()) {
    err << "too many arguments for format string (" << args.size()
        << " supplied, " << specs.size() << " expected)";
    return make_error<FormatError>(err.str());
  }

  // Walk over the arguments and check the most basic type information.
  static const std::vector<Type> any_integer = { Type::integer,
                                                 Type::boolean,
                                                 Type::pointer };
  static const std::map<std::string, std::vector<Type>> required_type = {
    { "d", any_integer },
    { "i", any_integer },
    { "u", any_integer },
    { "o", any_integer },
    { "x", any_integer },
    { "X", any_integer },
    { "c", any_integer },
    { "r", { Type::buffer } },
    { "rx", { Type::buffer } },
    { "rh", { Type::buffer } },
    { "s", {} },
    { "p", any_integer },
  };
  for (size_t i = 0; i < specs.size(); i++) {
    if (args[i].IsNoneTy() || args[i].IsVoidTy()) {
      err << "unable to print none type for specifier: " << specs[i].specifier;
      return make_error<FormatError>(err.str());
    }
    auto it = required_type.find(specs[i].specifier);
    if (it == required_type.end()) {
      err << "unsupported format specifier: " << specs[i].specifier;
      return make_error<FormatError>(err.str());
    }
    if (it->second.empty()) {
      // Anything goes.
      continue;
    }
    bool found = false;
    for (const auto& allowed : it->second) {
      if (args[i].GetTy() == allowed) {
        found = true;
        break;
      }
    }
    if (!found) {
      err << "unsupported format specifier for type '" << typestr(args[i])
          << "': " << specs[i].specifier;
      return make_error<FormatError>(err.str());
    }
  }
  return OK();
}

template <typename T, typename Cast = T>
Result<> as_number(std::stringstream& ss, const Primitive& p)
{
  return std::visit(
      [&](const auto& v) -> Result<> {
        if constexpr (std::is_same_v<std::decay_t<decltype(v)>,
                                     output::Primitive::Symbolic>) {
          return as_number<T, Cast>(ss, output::Primitive(v.numeric));
        } else if constexpr (std::is_same_v<std::decay_t<decltype(v)>,
                                            int64_t> ||
                             std::is_same_v<std::decay_t<decltype(v)>,
                                            uint64_t> ||
                             std::is_same_v<std::decay_t<decltype(v)>,
                                            double> ||
                             std::is_same_v<std::decay_t<decltype(v)>, bool>) {
          if constexpr (std::is_same_v<T, void*>) {
            ss << reinterpret_cast<void*>(static_cast<unsigned long long>(v));
          } else {
            ss << static_cast<T>(static_cast<Cast>(v));
          }
          return OK();
        } else {
          std::stringstream msg;
          msg << "invalid integer conversion: " << p;
          return make_error<FormatError>(msg.str());
        }
      },
      p.variant);
}

template <typename T = long long, typename Cast = int>
Result<> as_signed_integer(std::stringstream& ss,
                           const Primitive& p,
                           const std::string& length_modifier)
{
  if (length_modifier == "hh") {
    return as_number<T, char>(ss, p);
  } else if (length_modifier == "h") {
    return as_number<T, short>(ss, p);
  } else if (length_modifier == "l") {
    return as_number<T, long>(ss, p);
  } else if (length_modifier == "ll") {
    return as_number<T, long long>(ss, p);
  } else if (length_modifier == "j") {
    return as_number<T, intmax_t>(ss, p);
  } else if (length_modifier == "z") {
    return as_number<T, ssize_t>(ss, p);
  } else if (length_modifier == "t") {
    return as_number<T, ptrdiff_t>(ss, p);
  } else {
    return as_number<T, Cast>(ss, p);
  }
}

template <typename T = unsigned long, typename Cast = unsigned int>
Result<> as_unsigned_integer(std::stringstream& ss,
                             const Primitive& p,
                             const std::string& length_modifier)
{
  if (length_modifier == "hh") {
    return as_number<T, unsigned char>(ss, p);
  } else if (length_modifier == "h") {
    return as_number<T, unsigned short>(ss, p);
  } else if (length_modifier == "l") {
    return as_number<T, unsigned long>(ss, p);
  } else if (length_modifier == "ll") {
    return as_number<T, unsigned long long>(ss, p);
  } else if (length_modifier == "j") {
    return as_number<T, uintmax_t>(ss, p);
  } else if (length_modifier == "z") {
    return as_number<T, size_t>(ss, p);
  } else if (length_modifier == "t") {
    return as_number<T, ptrdiff_t>(ss, p);
  } else {
    return as_number<T, Cast>(ss, p);
  }
}

Result<> as_floating_point(std::stringstream& ss,
                           const Primitive& p,
                           const std::string& length_modifier)
{
  if (length_modifier == "L") {
    return as_number<long double>(ss, p);
  } else {
    return as_number<double>(ss, p);
  }
}

static Result<> as_string(std::stringstream& ss,
                          const Primitive& p,
                          [[maybe_unused]] const std::string& length_modifier)
{
  ss << p;
  return OK();
}

template <bool keep_ascii = true, bool escape_hex = true>
static Result<> as_buffer(std::stringstream& ss,
                          const Primitive& p,
                          const std::string& length_modifier)
{
  if (std::holds_alternative<Primitive::Buffer>(p.variant)) {
    const auto& buf = std::get<Primitive::Buffer>(p.variant);
    ss << util::hex_format_buffer(
        buf.data.data(), buf.data.size(), keep_ascii, escape_hex);
    return OK();
  } else {
    return as_string(ss, p, length_modifier);
  }
}

Result<std::string> FormatSpec::apply(const Primitive& p) const
{
  std::stringstream ss;
  if (left_align) {
    ss << std::left;
  } else {
    ss << std::right;
  }
  if (width > 0) {
    ss << std::setw(width);
  }
  if (lead_zeros) {
    ss << std::setfill('0');
  }
  if (precision >= 0 &&
      (specifier == "f" || specifier == "F" || specifier == "e" ||
       specifier == "E" || specifier == "g" || specifier == "G" ||
       specifier == "a" || specifier == "A")) {
    ss << std::setprecision(precision);
    if (specifier == "f" || specifier == "F") {
      ss << std::fixed;
    } else if (specifier == "e" || specifier == "E") {
      ss << std::scientific;
    }
  }
  if (specifier == "o") {
    ss << std::oct;
  } else if (specifier == "x") {
    ss << std::hex << std::nouppercase;
  } else if (specifier == "X") {
    ss << std::hex << std::uppercase;
  }
  if (alternate_form) {
    ss << std::showbase;
  }
  if (show_sign) {
    ss << std::showpos;
  }
  using SpecifierHandler = Result<> (*)(std::stringstream&,
                                        const Primitive&,
                                        const std::string&);
  static const std::map<std::string, SpecifierHandler> specifier_dispatch = {
    { "d", as_signed_integer },
    { "i", as_signed_integer },
    { "u", as_unsigned_integer },
    { "o", as_unsigned_integer },
    { "x", as_unsigned_integer },
    { "X", as_unsigned_integer },
    { "f", as_floating_point },
    { "F", as_floating_point },
    { "e", as_floating_point },
    { "E", as_floating_point },
    { "g", as_floating_point },
    { "G", as_floating_point },
    { "a", as_floating_point },
    { "A", as_floating_point },
    { "c", as_signed_integer<char> },
    { "r", as_buffer },
    { "rx", as_buffer<false> },
    { "rh", as_buffer<false, false> },
    { "s", as_string },
    { "p", as_unsigned_integer<void*> },
  };

  auto* dispatcher = as_string; // Default.
  auto it = specifier_dispatch.find(specifier);
  if (it != specifier_dispatch.end()) {
    dispatcher = it->second;
  }
  auto ok = dispatcher(ss, p, length_modifier);
  if (!ok) {
    return ok.takeError();
  }
  return ss.str();
}

std::string FormatString::format(const std::vector<Primitive>& args) const
{
  std::stringstream ss;
  for (size_t i = 0; i < args.size(); i++) {
    ss << fragments[i];
    auto s = specs[i].apply(args[i]);
    if (s) {
      // Write the formatted string.
      ss << *s;
    } else {
      // Nothing has been written, so just embed the error into the string here.
      // This is what happens in `Go` when a value cannot be formatted properly.
      ss << "!{" << s.takeError() << "}";
    }
  }
  ss << fragments.back();
  return ss.str();
}

} // namespace bpftrace
