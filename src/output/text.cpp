#include <iomanip>
#include <string>

#include "output/text.h"
#include "util/strings.h"

namespace bpftrace::output {

template <typename T>
struct TextEmitter {
  static void emit(std::ostream &out, const T &v)
  {
    out << v;
  }
};

template <>
struct TextEmitter<bool> {
  static void emit(std::ostream &out, const bool &v)
  {
    if (v) {
      out << "true";
    } else {
      out << "false";
    }
  }
};

template <typename... Types>
struct TextEmitter<std::variant<Types...>> {
  static void emit(std::ostream &out, const std::variant<Types...> &v)
  {
    std::visit(
        [&](const auto &v) {
          TextEmitter<std::decay_t<decltype(v)>>::emit(out, v);
        },
        v);
  }
};

template <typename T>
struct TextEmitter<std::vector<T>> {
  static void emit(std::ostream &out, const std::vector<T> &v)
  {
    bool first = true;
    out << "[";
    for (const auto &elem : v) {
      if (!first) {
        out << ",";
      }
      TextEmitter<T>::emit(out, elem);
      first = false;
    }
    out << "]";
  }
};

template <>
struct TextEmitter<std::monostate> {
  static void emit(std::ostream &out, [[maybe_unused]] const std::monostate &v)
  {
    out << "null";
  }
};

template <>
struct TextEmitter<Primitive> {
  static void emit(std::ostream &out, const Primitive &v)
  {
    TextEmitter<Primitive::Variant>::emit(out, v.variant);
  }
};

template <>
struct TextEmitter<Primitive::Record> {
  static void emit(std::ostream &out, const Primitive::Record &v)
  {
    bool first = true;
    if (v.fields.empty()) {
      out << "{}";
      return;
    }
    out << "{ ";
    for (const auto &[key, elem] : v.fields) {
      if (!first) {
        out << ", "; // Structs always get spaces.
      }
      out << ".";
      TextEmitter<std::string>::emit(out, key);
      out << " = ";
      TextEmitter<Primitive>::emit(out, elem);
      first = false;
    }
    out << " }";
  }
};

template <>
struct TextEmitter<Primitive::Array> {
  static void emit(std::ostream &out, const Primitive::Array &v)
  {
    TextEmitter<std::vector<Primitive>>::emit(out, v.values);
  }
};

template <>
struct TextEmitter<Primitive::Buffer> {
  static void emit(std::ostream &out, const Primitive::Buffer &v)
  {
    TextEmitter<std::string>::emit(
        out, util::hex_format_buffer(v.data.data(), v.data.size()));
  }
};

template <>
struct TextEmitter<Primitive::Tuple> {
  static void emit(std::ostream &out, const Primitive::Tuple &v)
  {
    bool first = true;
    out << "(";
    for (const auto &elem : v.values) {
      if (!first) {
        out << ", "; // N.B. tuples get spaces, arrays do not.
      }
      TextEmitter<Primitive>::emit(out, elem);
      first = false;
    }
    out << ")";
  }
};

template <>
struct TextEmitter<Primitive::Symbolic> {
  static void emit(std::ostream &out, const Primitive::Symbolic &v)
  {
    // Always emit the symbolic value.
    TextEmitter<std::string>::emit(out, v.symbol);
  }
};

template <typename T, typename... Types>
static bool adjacent_values(const std::variant<Types...> &first,
                            const std::variant<Types...> &second)
{
  if (!std::holds_alternative<T>(first) || !std::holds_alternative<T>(second)) {
    return false;
  }
  return (std::get<T>(first) + static_cast<T>(1)) == std::get<T>(second);
}

static bool single_value(const Primitive &first, const Primitive &second)
{
  return adjacent_values<uint64_t>(first.variant, second.variant) ||
         adjacent_values<int64_t>(first.variant, second.variant);
}

template <>
struct TextEmitter<Value::Histogram> {
  static void emit(std::ostream &out, const Value::Histogram &hist)
  {
    uint64_t max_value = 0;
    for (const auto &v : hist.counts) {
      max_value = std::max(max_value, v);
    }
    for (size_t i = 0; i < hist.counts.size() || i < hist.labels.size(); i++) {
      int max_width = 52;
      int bar_width = (hist.counts.at(i) / static_cast<float>(max_value)) *
                      max_width;
      std::ostringstream header;
      if (i == 0) {
        if (!hist.lower_bound) {
          header << "(..., ";
          TextEmitter<Primitive>::emit(header, hist.labels[i]);
          header << ")";
        } else if (single_value(*hist.lower_bound, hist.labels[i])) {
          header << "[";
          TextEmitter<Primitive>::emit(header, *hist.lower_bound);
          header << "]";
        } else {
          header << "[";
          TextEmitter<Primitive>::emit(header, *hist.lower_bound);
          header << ", ";
          TextEmitter<Primitive>::emit(header, hist.labels[i]);
          header << ")";
        }
      } else if (i >= hist.labels.size()) {
        header << "[";
        TextEmitter<Primitive>::emit(header, hist.labels[i - 1]);
        header << ", ...)";
      } else if (single_value(hist.labels[i - 1], hist.labels[i])) {
        header << "[";
        TextEmitter<Primitive>::emit(header, hist.labels[i - 1]);
        header << "]";
      } else {
        header << "[";
        TextEmitter<Primitive>::emit(header, hist.labels[i - 1]);
        header << ", ";
        TextEmitter<Primitive>::emit(header, hist.labels[i]);
        header << ")";
      }
      std::string bar(bar_width, '@');
      out << std::setw(16) << std::left << header.str() << std::setw(8)
          << std::right << hist.counts.at(i) << " |" << std::setw(max_width)
          << std::left << bar << "|" << std::endl;
    }
  }
};

template <>
struct TextEmitter<Value> {
  static void emit(std::ostream &out, const Value &v)
  {
    TextEmitter<Value::Variant>::emit(out, v.variant);
  }
};

template <>
struct TextEmitter<Value::OrderedMap> {
  static void emit(std::ostream &out, const Value::OrderedMap &m)
  {
    for (const auto &[key, value] : m.values) {
      out << "[";
      TextEmitter<Primitive>::emit(out, key);
      out << "]: ";
      TextEmitter<Value>::emit(out, value);
      out << std::endl;
    }
  }
};

template <>
struct TextEmitter<Value::Stats> {
  static void emit(std::ostream &out, const Value::Stats &s)
  {
    TextEmitter<std::decay_t<decltype(s.value)>>::emit(out, s.value);
  }
};

static void emit_map(std::ostream &out,
                     const std::string &name,
                     const Value::OrderedMap &m)
{
  // For legacy reasons, this is printed with the map name each time. Also,
  // we have special behavior for the case of a tuple-based keys, wherein
  // the tuple parenthesis are explicitly omitted for this line only.
  for (const auto &[key, value] : m.values) {
    out << name << "[";
    std::stringstream ss;
    ss << key;
    auto s = ss.str();
    if (s.size() >= 2 && s[0] == '(' && s[s.size() - 1] == ')') {
      s = s.substr(1, s.size() - 2);
    }
    out << s;
    // If this is a primitive (and fits on a single line), then we emit
    // inline, otherwise we display the potentially multi-line value on
    // subsequent lines.
    if (!std::holds_alternative<Primitive>(value.variant)) {
      out << "]:";
      out << std::endl;
    } else {
      out << "]: ";
    }
    TextEmitter<Value>::emit(out, value);
    out << std::endl;
  }
}

void TextOutput::map(const std::string &name, const Value &value)
{
  if (std::holds_alternative<Value::Histogram>(value.variant) ||
      std::holds_alternative<std::vector<Value>>(value.variant)) {
    // These are printed on separate lines.
    out_ << name << ":" << std::endl;
    TextEmitter<Value>::emit(out_, value);
    out_ << std::endl;
  } else if (std::holds_alternative<Value::Stats>(value.variant)) {
    // Treat this as the top-level value and unpack.
    auto stats = std::get<Value::Stats>(value.variant);
    if (std::holds_alternative<Value::OrderedMap>(stats.value)) {
      // Print as a normal map, per below.
      emit_map(out_, name, std::get<Value::OrderedMap>(stats.value));
    } else {
      // Print as a normal value, per below.
      out_ << name << ": ";
      TextEmitter<Primitive>::emit(out_, std::get<Primitive>(stats.value));
      out_ << std::endl;
    }
  } else if (std::holds_alternative<Value::OrderedMap>(value.variant)) {
    emit_map(out_, name, std::get<Value::OrderedMap>(value.variant));
  } else {
    // Single value.
    out_ << name << ": ";
    TextEmitter<Value>::emit(out_, value);
    out_ << std::endl;
  }
}

void TextOutput::value(const Value &value)
{
  TextEmitter<Value>::emit(out_, value);
  out_ << std::endl;
}

void TextOutput::primitive(const Primitive &p)
{
  TextEmitter<Primitive>::emit(out_, p);
}

void TextOutput::printf(const std::string &str)
{
  out_ << str;
}

void TextOutput::time(const std::string &time)
{
  out_ << time;
}

void TextOutput::cat(const std::string &cat)
{
  out_ << cat;
}

void TextOutput::join(const std::string &join)
{
  out_ << join << std::endl;
}

void TextOutput::syscall(const std::string &syscall)
{
  out_ << syscall << std::endl;
}

void TextOutput::lost_events(uint64_t lost)
{
  out_ << "Lost " << lost << " events" << std::endl;
}

void TextOutput::attached_probes(uint64_t num_probes)
{
  if (num_probes == 1)
    out_ << "Attached " << num_probes << " probe" << std::endl;
  else
    out_ << "Attached " << num_probes << " probes" << std::endl;
}

void TextOutput::helper_error(int retcode, const HelperErrorInfo &info)
{
  std::string msg;
  if (info.func_id == libbpf::BPF_FUNC_map_update_elem && retcode == -E2BIG) {
    msg = "Map full; can't update element. Try increasing max_map_keys config "
          "or manually setting the max entries in a map declaration e.g. `let "
          "@a = hash(5000)`";
  } else if (info.func_id == libbpf::BPF_FUNC_map_delete_elem &&
             retcode == -ENOENT) {
    msg = "Can't delete map element because it does not exist.";
  }
  // bpftrace sets the return code to 0 for map_lookup_elem failures
  // which is why we're not also checking the retcode
  else if (info.func_id == libbpf::BPF_FUNC_map_lookup_elem) {
    msg = "Can't lookup map element because it does not exist.";
  } else {
    msg = strerror(-retcode);
  }

  LOG(WARNING,
      std::string(info.source_location),
      std::vector(info.source_context),
      out_)
      << msg << "\nAdditional Info - helper: " << info.func_id
      << ", retcode: " << retcode;
}

void TextOutput::end()
{
  out_ << std::endl;
  out_ << std::endl;
}

} // namespace bpftrace::output
