#include <iomanip>
#include <string>

#include "output/json.h"

namespace bpftrace::output {

template <typename T>
struct JsonEmitter;

template <>
struct JsonEmitter<bool> {
  static void emit(std::ostream &out, const bool &v)
  {
    if (v) {
      out << "true";
    } else {
      out << "false";
    }
  }
};

template <>
struct JsonEmitter<std::string> {
  static void emit(std::ostream &out, const std::string &s)
  {
    out << "\"";
    for (const char c : s) {
      switch (c) {
        case '"':
          out << "\\\"";
          break;

        case '\\':
          out << "\\\\";
          break;

        case '\n':
          out << "\\n";
          break;

        case '\r':
          out << "\\r";
          break;

        case '\t':
          out << "\\t";
          break;

        default:
          // c always >= '\x00'
          if (c <= '\x1f') {
            out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                << static_cast<int>(c);
          } else {
            out << c;
          }
      }
    }
    out << "\"";
  }
};

template <typename T>
  requires(std::is_same_v<T, int64_t> || std::is_same_v<T, uint64_t> ||
           std::is_same_v<T, int32_t> || std::is_same_v<T, uint32_t> ||
           std::is_same_v<T, double> || std::is_same_v<T, char>)
struct JsonEmitter<T> {
  static void emit(std::ostream &out, const T &v)
  {
    // JSON does not support numbers other than floating point, therefore
    // we emit int64_t as a string if it is not representable as a 64-bit
    // floating point. This is encoded in the spec in RFC 8259, and is a
    // common footgun people encounter at some point after choosing JSON.
    auto s = std::to_string(v);
    if constexpr (!std::is_same_v<T, double>) {
      if (static_cast<T>(static_cast<double>(v)) != v) {
        return JsonEmitter<std::string>::emit(out, s);
      }
    }
    out << s;
  }
};

template <typename K, typename V>
struct JsonEmitter<std::vector<std::pair<K, V>>> {
  static void emit(std::ostream &out, const std::vector<std::pair<K, V>> &m)
  {
    out << "{";
    bool first = true;
    for (const auto &[key, value] : m) {
      if (!first) {
        out << ", "; // N.B. Objects are spaced, see below.
      }

      // Keys are always converted to strings. If this corresponds to a tuple
      // string (e.g. "(1, 2)"), then we explicitly strip off the parentheses.
      std::string s;
      if constexpr (std::is_same_v<std::decay_t<decltype(key)>, std::string>) {
        s = key;
      } else {
        std::stringstream ss;
        ss << Primitive(key);
        s = ss.str();
        if (s.size() >= 2 && s[0] == '(' && s[s.size() - 1] == ')') {
          s = s.substr(1, s.size() - 2);
        }
        // We also don't like spaces in the key, so we strip those too. Note
        // that this is different from the text representation, which does
        // still include spaces for most tuples.
        std::erase(s, ' ');
      }
      JsonEmitter<std::string>::emit(out, s);

      // Leave the values as they are.
      out << ": ";
      JsonEmitter<std::decay_t<decltype(value)>>::emit(out, value);
      first = false;
    }
    out << "}";
  }
};

template <typename T>
struct JsonEmitter<std::vector<T>> {
  static void emit(std::ostream &out, const std::vector<T> &v)
  {
    out << "[";
    bool first = true;
    for (const auto &elem : v) {
      if (!first) {
        out << ","; // N.B. Arrays are unspaced, see above.
      }
      JsonEmitter<T>::emit(out, elem);
      first = false;
    }
    out << "]";
  }
};

template <typename... Types>
struct JsonEmitter<std::variant<Types...>> {
  static void emit(std::ostream &out, const std::variant<Types...> &v)
  {
    std::visit(
        [&](const auto &v) {
          JsonEmitter<std::decay_t<decltype(v)>>::emit(out, v);
        },
        v);
  }
};

template <>
struct JsonEmitter<std::monostate> {
  static void emit(std::ostream &out, [[maybe_unused]] const std::monostate &v)
  {
    out << "null";
  }
};

template <>
struct JsonEmitter<Primitive> {
  static void emit(std::ostream &out, const Primitive &v)
  {
    JsonEmitter<Primitive::Variant>::emit(out, v.variant);
  }
};

template <>
struct JsonEmitter<Primitive::Record> {
  static void emit(std::ostream &out, const Primitive::Record &v)
  {
    JsonEmitter<std::decay_t<decltype(v.fields)>>::emit(out, v.fields);
  }
};

template <>
struct JsonEmitter<Primitive::Array> {
  static void emit(std::ostream &out, const Primitive::Array &v)
  {
    JsonEmitter<std::vector<Primitive>>::emit(out, v.values);
  }
};

template <>
struct JsonEmitter<Primitive::Buffer> {
  static void emit(std::ostream &out, const Primitive::Buffer &v)
  {
    JsonEmitter<std::vector<char>>::emit(out, v.data);
  }
};

template <>
struct JsonEmitter<Primitive::Tuple> {
  static void emit(std::ostream &out, const Primitive::Tuple &v)
  {
    if (v.is_named) {
      JsonEmitter<std::decay_t<decltype(v.fields)>>::emit(out, v.fields);
    } else {
      std::vector<Primitive> values;
      for (const auto &[key, elem] : v.fields) {
        values.emplace_back(elem);
      }
      JsonEmitter<std::vector<Primitive>>::emit(out, values);
    }
  }
};

template <>
struct JsonEmitter<Primitive::Symbolic> {
  static void emit(std::ostream &out, const Primitive::Symbolic &v)
  {
    // JSON does not emit symbolic values.
    JsonEmitter<uint64_t>::emit(out, v.numeric);
  }
};

template <>
struct JsonEmitter<Primitive::Timestamp> {
  static void emit(std::ostream &out, const Primitive::Timestamp &v)
  {
    std::stringstream ss;
    ss << v; // Use default representation.
    JsonEmitter<std::string>::emit(out, ss.str());
  }
};

template <>
struct JsonEmitter<Primitive::Duration> {
  static void emit(std::ostream &out, const Primitive::Duration &v)
  {
    std::stringstream ss;
    ss << v; // Use default representation.
    JsonEmitter<std::string>::emit(out, ss.str());
  }
};

template <typename T>
std::optional<int64_t> one_less(const T &v)
{
  if constexpr (std::is_same_v<T, Primitive::Symbolic>) {
    return one_less(v.numeric);
  } else if constexpr (std::is_same_v<T, int64_t>) {
    return v - 1;
  } else if constexpr (std::is_same_v<T, uint64_t>) {
    if (v == 0) {
      return -1;
    } else {
      // N.B. This can overflow, but what can we do? We can't even encode this
      // integer into JSON properly, so this isn't the biggest problem.
      return static_cast<int64_t>(v - 1);
    }
  } else if constexpr (std::is_same_v<T, Primitive>) {
    // Try to recursively unpack the value and return one less.
    return std::visit([](const auto &v) { return one_less(v); }, v.variant);
  } else {
    // Give up.
    return std::nullopt;
  }
}

template <>
struct JsonEmitter<Value::Histogram> {
  static void emit(std::ostream &out, const Value::Histogram &hist)
  {
    out << "[";
    bool first = true;
    for (size_t i = 0; i < hist.counts.size(); i++) {
      if (!first) {
        out << ",";
      }
      out << "{";
      if (i == 0 && hist.lower_bound) {
        out << "\"min\": ";
        JsonEmitter<Primitive>::emit(out, *hist.lower_bound);
        out << ", ";
      } else if (i > 0) {
        out << "\"min\": ";
        JsonEmitter<Primitive>::emit(out, hist.labels[i - 1]);
        out << ", ";
      }
      if (i < hist.labels.size()) {
        // For whatever reason, the open-intervals for the JSON encoding are
        // not open-intervals, they are closed intervals. So we need to
        // subtract one from the integer extracted here.
        //
        // If we can't find a suitable "one less" representation, then we
        // just emit the label as is (be it string, whatever).
        out << "\"max\": ";
        auto v = one_less(hist.labels[i]);
        if (v) {
          JsonEmitter<int64_t>::emit(out, *v);
        } else {
          JsonEmitter<Primitive>::emit(out, hist.labels[i]);
        }
        out << ", ";
      }
      out << "\"count\": " << hist.counts[i];
      out << "}";
      first = false;
    }
    out << "]";
  }
};

template <>
struct JsonEmitter<Value::OrderedMap> {
  static void emit(std::ostream &out, const Value::OrderedMap &m)
  {
    JsonEmitter<std::decay_t<decltype(m.values)>>::emit(out, m.values);
  }
};

template <>
struct JsonEmitter<Value::Stats> {
  static void emit(std::ostream &out, const Value::Stats &s)
  {
    JsonEmitter<std::decay_t<decltype(s.value)>>::emit(out, s.value);
  }
};

template <>
struct JsonEmitter<Value::TimeSeries> {
  static void emit(std::ostream &out, const Value::TimeSeries &tseries)
  {
    bool first = true;
    out << "[";
    for (const auto &[ts, value] : tseries.values) {
      if (std::holds_alternative<std::monostate>(value.variant)) {
        continue;
      }
      if (first) {
        first = false;
      } else {
        out << ",";
      }
      out << R"({"interval_start":")" << ts << R"(","value":)" << value << "}";
    }
    out << "]";
  }
};

template <>
struct JsonEmitter<Value> {
  static void emit(std::ostream &out, const Value &v)
  {
    JsonEmitter<Value::Variant>::emit(out, v.variant);
  }
};

template <typename T>
void emit_data(std::ostream &out,
               const std::string &type,
               std::optional<std::string> &&name,
               const T &v)
{
  out << R"({"type": ")" << type << R"(", "data": )";
  if (name) {
    out << "{";
    JsonEmitter<std::string>::emit(out, *name);
    out << ": ";
  }
  JsonEmitter<T>::emit(out, v);
  if (name) {
    out << "}";
  }
  out << "}" << std::endl;
}

template <typename T>
bool has_type(const Value &value)
{
  if (std::holds_alternative<T>(value.variant)) {
    return true;
  }
  if (std::holds_alternative<std::vector<Value>>(value.variant)) {
    const auto &vec = std::get<std::vector<Value>>(value.variant);
    if (!vec.empty()) {
      return has_type<T>(vec.at(0));
    }
  }
  if (std::holds_alternative<Value::OrderedMap>(value.variant)) {
    const auto &m = std::get<Value::OrderedMap>(value.variant);
    if (!m.values.empty()) {
      return has_type<T>(m.values.at(0).second);
    }
  }
  return false;
}

void JsonOutput::map(const std::string &name, const Value &value)
{
  if (std::holds_alternative<Value::OrderedMap>(value.variant)) {
    if (std::get<Value::OrderedMap>(value.variant).values.empty()) {
      return;
    }
  }

  // If the value is a histogram, or a map of histograms, then we set the type
  // to `hist`. If it is explicitly a `stats` map, then set that type.
  // Otherwise, just set the message type to `map`.
  std::string type = "map";
  if (has_type<Value::Stats>(value)) {
    type = "stats";
  } else if (has_type<Value::TimeSeries>(value)) {
    type = "tseries";
  } else if (has_type<Value::Histogram>(value)) {
    type = "hist";
  }
  emit_data(out_, type, name, value);
}

void JsonOutput::value(const Value &value)
{
  emit_data(out_, "value", std::nullopt, value);
}

void JsonOutput::printf(const std::string &str,
                        const SourceInfo &info,
                        PrintfSeverity severity)
{
  switch (severity) {
    case PrintfSeverity::NONE: {
      emit_data(out_, "printf", std::nullopt, str);
      return;
    }
    case PrintfSeverity::WARNING:
    case PrintfSeverity::ERROR: {
      bool is_error = severity == PrintfSeverity::ERROR;
      out_ << R"({"type": ")" << (is_error ? "errorf" : "warnf") << "\"";
      out_ << R"(, "msg": )";
      std::stringstream ss;
      ss << str;
      JsonEmitter<std::string>::emit(out_, ss.str());
      // Json only prints the top level location
      out_ << R"(, "filename": )";
      JsonEmitter<std::string>::emit(out_, info.locations.begin()->filename);
      out_ << R"(, "line": )";
      JsonEmitter<uint64_t>::emit(out_, info.locations.begin()->line);
      out_ << R"(, "col": )";
      JsonEmitter<uint64_t>::emit(out_, info.locations.begin()->column);
      out_ << R"(})" << std::endl;
      return;
    }
  }
}

void JsonOutput::time(const std::string &time)
{
  emit_data(out_, "time", std::nullopt, time);
}

void JsonOutput::cat(const std::string &cat)
{
  emit_data(out_, "cat", std::nullopt, cat);
}

void JsonOutput::join(const std::string &join)
{
  emit_data(out_, "join", std::nullopt, join);
}

void JsonOutput::syscall(const std::string &syscall)
{
  emit_data(out_, "syscall", std::nullopt, syscall);
}

void JsonOutput::lost_events(uint64_t lost)
{
  // This is a special case, it emits both a count and the `data` field.
  out_ << R"({"type": "lost_events", "count": )" << lost
       << R"(, "data": {"events": )" << lost << "}}" << std::endl;
}

void JsonOutput::attached_probes(uint64_t num_probes)
{
  // As with lost_events, this is a special case, we do a `count` and `data`
  // field.
  out_ << R"({"type": "attached_probes", "count": )" << num_probes
       << R"(, "data": {"probes": )" << num_probes << "}}" << std::endl;
}

void JsonOutput::runtime_error(int retcode, const RuntimeErrorInfo &info)
{
  switch (info.error_id) {
    case RuntimeErrorId::HELPER_ERROR: {
      out_ << R"({"type": "helper_error")";
      out_ << R"(, "msg": )";
      JsonEmitter<std::string>::emit(out_, strerror(-retcode));
      out_ << R"(, "helper": )";
      std::stringstream ss;
      ss << info.func_id;
      JsonEmitter<std::string>::emit(out_, ss.str());
      out_ << R"(, "retcode": )";
      JsonEmitter<int64_t>::emit(out_, retcode);
      break;
    }
    default: {
      out_ << R"({"type": "runtime_error")";
      out_ << R"(, "msg": )";
      std::stringstream ss;
      ss << info;
      JsonEmitter<std::string>::emit(out_, ss.str());
      break;
    }
  }

  // Json only prints the top level location
  out_ << R"(, "filename": )";
  JsonEmitter<std::string>::emit(out_, info.locations.begin()->filename);
  out_ << R"(, "line": )";
  JsonEmitter<uint64_t>::emit(out_, info.locations.begin()->line);
  out_ << R"(, "col": )";
  JsonEmitter<uint64_t>::emit(out_, info.locations.begin()->column);
  out_ << R"(})" << std::endl;
}

void JsonOutput::test_result(const std::vector<std::string> &all_tests,
                             size_t index,
                             std::chrono::nanoseconds duration,
                             const std::vector<bool> &passed,
                             std::string output)
{
  Primitive::Record result;
  result.fields.emplace_back("duration", duration.count());
  result.fields.emplace_back("passed", passed[index]);
  result.fields.emplace_back("output", output);
  emit_data(out_, "test_result", all_tests[index], result);
}

void JsonOutput::benchmark_result(const std::vector<std::string> &all_benches,
                                  size_t index,
                                  std::chrono::nanoseconds average,
                                  size_t iters)
{
  Primitive::Record result;
  result.fields.emplace_back("average", average.count());
  result.fields.emplace_back("iters", iters);
  emit_data(out_, "benchmark_result", all_benches[index], result);
}

void JsonOutput::end()
{
  // Nothing emitted.
}

} // namespace bpftrace::output
