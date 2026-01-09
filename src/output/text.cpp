#include <algorithm>
#include <bpf/bpf.h>
#include <iomanip>
#include <string>

#include "log.h"
#include "output/text.h"
#include "util/strings.h"
#include "util/time.h"

namespace bpftrace::output {

using namespace std::chrono_literals;

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
    for (const auto &[key, elem] : v.fields) {
      if (!first) {
        out << ", "; // N.B. tuples get spaces, arrays do not.
      }
      if (v.is_named) {
        TextEmitter<std::string>::emit(out, key);
        out << " = ";
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

template <>
struct TextEmitter<Primitive::Timestamp> {
  static void emit(std::ostream &out,
                   const Primitive::Timestamp &v,
                   const std::string &format = "%Y-%m-%dT%H:%M:%S",
                   const util::DisplayUnit &unit = util::DisplayUnit::ns)
  {
    // Emit the time point in the ISO 8601 form.
    auto s = std::chrono::time_point_cast<std::chrono::seconds>(v);
    auto ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(v - s).count();
    std::time_t t = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::time_point(s.time_since_epoch()));
    std::tm tm;
    localtime_r(&t, &tm);
    std::stringstream ss;
    ss << std::put_time(&tm, format.c_str());
    switch (unit) {
      case util::DisplayUnit::ns:
        ss << "." << std::setw(9) << std::setfill('0') << ns;
        break;
      case util::DisplayUnit::us:
        ss << "." << std::setw(6) << std::setfill('0') << ns / 1000;
        break;
      case util::DisplayUnit::ms:
        ss << "." << std::setw(3) << std::setfill('0') << ns / 1000000;
        break;
      default:
        // No additional trailing seconds.
        break;
    }
    TextEmitter<std::string>::emit(out, ss.str());
  }
};

template <>
struct TextEmitter<Primitive::Duration> {
  static void emit(std::ostream &out, const Primitive::Duration &v)
  {
    // Just emit a string with the duration in human-readable format.
    auto [unit, scale] = util::duration_str(v);
    out << (v.count() / scale) << unit;
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
        } else if (hist.labels.empty()) {
          // Histogram contains overflow-only case
          header << "[";
          TextEmitter<Primitive>::emit(header, *hist.lower_bound);
          header << ", ...)";
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

static void try_dec(Primitive &p)
{
  if (std::holds_alternative<uint64_t>(p.variant) &&
      std::get<uint64_t>(p.variant) > std::numeric_limits<uint64_t>::min()) {
    std::get<uint64_t>(p.variant)--;
  } else if (std::holds_alternative<int64_t>(p.variant) &&
             std::get<int64_t>(p.variant) >
                 std::numeric_limits<int64_t>::min()) {
    std::get<int64_t>(p.variant)--;
  }
}

static void try_inc(Primitive &p)
{
  if (std::holds_alternative<uint64_t>(p.variant) &&
      std::get<uint64_t>(p.variant) < std::numeric_limits<uint64_t>::max()) {
    std::get<uint64_t>(p.variant)++;
  } else if (std::holds_alternative<int64_t>(p.variant) &&
             std::get<int64_t>(p.variant) <
                 std::numeric_limits<int64_t>::max()) {
    std::get<int64_t>(p.variant)++;
  }
}

static int64_t distance(const Primitive &p, int64_t other)
{
  if (std::holds_alternative<uint64_t>(p.variant)) {
    const auto &v = std::get<uint64_t>(p.variant);
    if (other < 0) {
      return static_cast<uint64_t>(-other) + v;
    }
    if (v > static_cast<uint64_t>(other)) {
      return static_cast<int64_t>(v - static_cast<uint64_t>(other));
    } else {
      return -static_cast<int64_t>(static_cast<uint64_t>(other) - v);
    }
  }
  if (std::holds_alternative<int64_t>(p.variant)) {
    const auto &v = std::get<int64_t>(p.variant);
    return v - other;
  }
  return 0;
}

static int64_t distance(const Primitive &p, const Primitive &other)
{
  if (std::holds_alternative<int64_t>(other.variant)) {
    return distance(p, std::get<int64_t>(other.variant));
  } else if (std::holds_alternative<uint64_t>(other.variant)) {
    return distance(p, static_cast<int64_t>(std::get<uint64_t>(other.variant)));
  } else {
    return 0; // Only handle integer primitives for now.
  }
}

template <>
struct TextEmitter<Value::TimeSeries> {
  static void emit(std::ostream &out, const Value::TimeSeries &ts)
  {
    constexpr int graph_width = 53;

    if (ts.values.empty()) {
      out << "<no data>";
      return;
    }

    std::vector<std::string> times;
    output::Primitive min_value = ts.values.front().second;
    output::Primitive max_value = ts.values.front().second;
    for (const auto &[epoch, v] : ts.values) {
      if (std::holds_alternative<std::monostate>(v.variant)) {
        continue; // Skip missing values.
      }
      if (v < min_value) {
        min_value = v;
      }
      if (v > max_value) {
        max_value = v;
      }
    }
    if (min_value == max_value) {
      // Generally prefer if we can add some buffer on both sides of the
      // points in the graph, but don't overflow if our min or max is at the
      // upper bound of the range.
      try_dec(min_value);
      try_inc(max_value);
    }

    // Figure out the interval.
    const auto interval = (ts.values.back().first - ts.values.front().first) /
                          (ts.values.size() > 1 ? ts.values.size() - 1 : 1);
    const auto [unit, scale] = util::duration_str(interval);
    std::string time_fmt = "hh:mm:ss";
    size_t time_size = time_fmt.size();
    if (unit > util::DisplayUnit::s) {
      std::stringstream ss;
      ss << "." << unit;
      time_fmt += ss.str();
      time_size += 1 + static_cast<size_t>(unit); // See DisplayUnit.
    }

    static const char *time_format = "%H:%M:%S";
    constexpr int padding = 21;
    std::stringstream res;
    res << std::setw(time_size + 1) << "";
    res << std::setw(padding);
    res << std::left;
    TextEmitter<Primitive>::emit(res, min_value);
    res << std::setw(graph_width - padding);
    res << std::right;
    TextEmitter<Primitive>::emit(res, max_value);
    res << std::endl;
    std::string top(graph_width - 2, '_');
    res << std::setw(time_size + 1) << std::left << time_fmt;
    res << "|" << top << "|" << std::endl;

    int zero_offset = 0;
    if (distance(min_value, 0) < 0 && distance(0, max_value) < 0) {
      zero_offset = static_cast<float>(graph_width) *
                    static_cast<float>(distance(min_value, 0)) /
                    static_cast<float>(distance(min_value, max_value));
    }
    for (const auto &[epoch, v] : ts.values) {
      std::string line(graph_width, ' ');
      TextEmitter<Primitive::Timestamp>::emit(res, epoch, time_format, unit);
      res << " ";

      line[0] = '|';
      line[graph_width - 1] = '|';
      if (zero_offset > 0) {
        line[zero_offset] = '.';
      }
      // There may be epochs with no valid entry.
      if (!std::holds_alternative<std::monostate>(v.variant)) {
        int point_offset = graph_width / 2;
        if (min_value != max_value) {
          point_offset = static_cast<float>(graph_width - 1) *
                         static_cast<float>(distance(min_value, v)) /
                         static_cast<float>(distance(min_value, max_value));
        }
        // Ensure that we don't have floating point issues.
        line[std::max(0, std::min(graph_width - 1, point_offset))] = '*';
        res << line << " ";
        TextEmitter<Primitive>::emit(res, v);
      } else {
        res << line << " -";
      }
      res << std::endl;
    }

    std::string bottom(graph_width, '_');
    bottom[0] = 'v';
    bottom[graph_width - 1] = 'v';
    res << std::setw(time_size) << "" << " " << bottom << std::endl;
    res << std::setw(time_size) << "" << " ";
    res << std::setw(padding);
    res << std::left;
    TextEmitter<Primitive>::emit(res, min_value);
    res << std::setw(graph_width - padding);
    res << std::right;
    TextEmitter<Primitive>::emit(res, max_value);
    res << std::endl;
    out << res.str();
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
      std::holds_alternative<std::vector<Value>>(value.variant) ||
      std::holds_alternative<Value::TimeSeries>(value.variant)) {
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

void TextOutput::printf(const std::string &str,
                        const SourceInfo &info,
                        PrintfSeverity severity)
{
  switch (severity) {
    case PrintfSeverity::NONE: {
      out_ << str;
      return;
    }
    case PrintfSeverity::WARNING:
    case PrintfSeverity::ERROR: {
      bool is_error = severity == PrintfSeverity::ERROR;
      bool first = true;
      for (const auto &loc : info.locations) {
        if (first) {
          // No need to print the source context as that's just the `errorf` or
          // `warnf` call
          if (is_error) {
            LOG(ERROR, std::string(loc.source_location), err_) << str;
          } else {
            LOG(WARNING, std::string(loc.source_location), err_) << str;
          }
          first = false;
        } else {
          if (is_error) {
            LOG(ERROR,
                std::string(loc.source_location),
                std::vector(loc.source_context),
                err_)
                << "expanded from";
          } else {
            LOG(WARNING,
                std::string(loc.source_location),
                std::vector(loc.source_context),
                err_)
                << "expanded from";
          }
        }
      }
      return;
    }
  }
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
  err_ << "Lost " << lost << " events" << std::endl;
}

void TextOutput::attached_probes(uint64_t num_probes)
{
  if (num_probes == 1)
    err_ << "Attached " << num_probes << " probe" << std::endl;
  else
    err_ << "Attached " << num_probes << " probes" << std::endl;
}

void TextOutput::runtime_error(int retcode, const RuntimeErrorInfo &info)
{
  switch (info.error_id) {
    case RuntimeErrorId::HELPER_ERROR: {
      std::string msg;
      if (info.func_id == BPF_FUNC_map_update_elem && retcode == -E2BIG) {
        msg = "Map full; can't update element. Try increasing max_map_keys "
              "config "
              "or manually setting the max entries in a map declaration e.g. "
              "`let "
              "@a = hash(5000)`";
      } else if (info.func_id == BPF_FUNC_map_delete_elem &&
                 retcode == -ENOENT) {
        msg = "Can't delete map element because it does not exist.";
      }
      // bpftrace sets the return code to 0 for map_lookup_elem failures
      // which is why we're not also checking the retcode
      else if (info.func_id == BPF_FUNC_map_lookup_elem) {
        msg = "Can't lookup map element because it does not exist.";
      } else {
        msg = strerror(-retcode);
      }

      LOG(WARNING,
          std::string(info.locations.begin()->source_location),
          std::vector(info.locations.begin()->source_context),
          err_)
          << msg << "\nAdditional Info - helper: " << info.func_id
          << ", retcode: " << retcode;
      break;
    }
    default: {
      LOG(WARNING,
          std::string(info.locations.begin()->source_location),
          std::vector(info.locations.begin()->source_context),
          err_)
          << info;
      break;
    }
  }

  // Print the chain
  for (size_t i = 1; i < info.locations.size(); ++i) {
    LOG(WARNING,
        std::string(info.locations[i].source_location),
        std::vector(info.locations[i].source_context),
        err_)
        << "expanded from";
  }
}

void TextOutput::test_result(const std::vector<std::string> &all_tests,
                             size_t index,
                             std::chrono::nanoseconds duration,
                             const std::vector<bool> &passed,
                             std::string output)
{
  if (index == 0) {
    out_ << "\033[32m[==========]\033[0m Running " << all_tests.size()
         << " tests." << std::endl;
  }
  out_ << "\033[32m[ RUN      ]\033[0m " << all_tests[index] << std::endl;

  // If the test has passed, we suppress any output. If it does not pass, then
  // we dump the output betwween the RUN and FAIL lines.
  if (passed[index]) {
    out_ << "\033[32m[       OK ]\033[0m " << all_tests[index];
  } else {
    auto lines = util::split_string(output, '\n');
    for (const auto &line : lines) {
      if (!line.empty()) {
        out_ << line << std::endl;
      }
    }
    out_ << "\033[31m[  FAILED  ]\033[0m " << all_tests[index];
  }
  auto [unit, val] = util::duration_str(duration);
  out_ << " (" << val << " " << unit << ")" << std::endl;

  auto test_or_tests = [](size_t n) { return n == 1 ? "test" : "tests"; };
  if (index == all_tests.size() - 1) {
    // Print the summary of what happened.
    out_ << "\033[32m[==========]\033[0m " << all_tests.size() << " "
         << test_or_tests(all_tests.size()) << " ran." << std::endl;
    // Count the number of passed and failed tests.
    auto failed_count = std::count(passed.begin(), passed.end(), false);
    auto passed_count = std::count(passed.begin(), passed.end(), true);
    out_ << "\033[32m[  PASSED  ]\033[0m " << passed_count << " "
         << test_or_tests(passed_count) << "." << std::endl;
    // We provide a detailed summary of all failed tests.
    if (failed_count > 0) {
      out_ << "\033[31m[  FAILED  ]\033[0m " << failed_count << " "
           << test_or_tests(failed_count) << ", listed below:" << std::endl;
      for (size_t i = 0; i < all_tests.size(); i++) {
        if (!passed[i]) {
          out_ << "\033[31m[  FAILED  ]\033[0m " << all_tests[i] << std::endl;
        }
      }
    }
  }
}

void TextOutput::benchmark_result(const std::vector<std::string> &all_benches,
                                  size_t index,
                                  std::chrono::nanoseconds average,
                                  size_t iters)
{
  const std::string BENCHMARK = "Benchmark";
  const std::string AVERAGE_TIME = "Time(ns)";
  const std::string ITERATIONS = "Iterations";
  size_t longest_name = std::max(static_cast<size_t>(40), BENCHMARK.size());
  size_t time_width = 15;

  for (const auto &name : all_benches) {
    longest_name = std::max(longest_name, name.size());
  }

  if (index == 0) {
    out_ << std::left << std::setw(longest_name + 1) << std::setfill(' ')
         << BENCHMARK;
    out_ << std::left << std::setw(time_width) << std::setfill(' ')
         << AVERAGE_TIME;
    out_ << std::left << ITERATIONS;
    out_ << std::endl;
    out_ << std::string(longest_name + 1 + time_width + ITERATIONS.size(), '-')
         << std::endl;
  }

  out_ << std::left << std::setw(longest_name + 1) << std::setfill(' ')
       << all_benches[index];
  out_ << std::left << std::setw(time_width) << std::setfill(' ')
       << average.count();
  out_ << std::left << iters;
  out_ << std::endl;
}

void TextOutput::end()
{
  out_ << std::endl;
  out_ << std::endl;
}

} // namespace bpftrace::output
