#pragma once

#include <cassert>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace bpftrace {

namespace LogColor {
constexpr const char* RESET = "\033[0m";
constexpr const char* RED = "\033[31m";
constexpr const char* YELLOW = "\033[33m";
constexpr const char* DEFAULT = "";
} // namespace LogColor

// clang-format off
enum class LogType
{
  DEBUG,
  V1,
  HINT,
  WARNING,
  ERROR,
  BUG,
};
// clang-format on

class Log {
public:
  Log(const Log& other) = delete;
  Log& operator=(const Log& other) = delete;
  Log(Log&& other) = delete;
  Log& operator=(Log&& other) = delete;

  static Log& get();

  void take_input(LogType type,
                  std::optional<std::string>&& source_location,
                  std::optional<std::vector<std::string>>&& source_context,
                  std::ostream& out,
                  std::string&& msg);

  void enable(LogType type)
  {
    enabled_map_[type] = true;
  }
  void disable(LogType type)
  {
    assert(type != LogType::BUG && type != LogType::ERROR);
    enabled_map_[type] = false;
  }
  bool is_enabled(LogType type)
  {
    return enabled_map_[type];
  }
  void set_colorize(bool is_colorize)
  {
    is_colorize_ = is_colorize;
  }

private:
  Log();
  ~Log() = default;

  std::unordered_map<LogType, bool> enabled_map_;
  bool is_colorize_ = false;
};

class LogStream {
public:
  LogStream(const std::string& file,
            int line,
            LogType type,
            std::ostream& out = std::cerr);
  LogStream(const std::string& file,
            int line,
            LogType type,
            std::string&& source_location,
            std::ostream& out = std::cerr);
  LogStream(const std::string& file,
            int line,
            LogType type,
            std::string&& source_location,
            std::vector<std::string>&& source_context,
            std::ostream& out = std::cerr);

  template <typename T>
  LogStream& operator<<(const T& v)
  {
    auto& sink = Log::get();
    if (sink.is_enabled(type_))
      buf_ << v;
    return *this;
  }
  virtual ~LogStream();

protected:
  // This formats the `file_` and `line_` and may be used to prefix the message
  // for some types of log streams.
  std::string internal_location();

  const std::string& file_;
  const int line_;
  LogType type_;
  std::optional<std::string> source_location_;
  std::optional<std::vector<std::string>> source_context_;
  std::ostream& out_;
  std::ostringstream buf_;
};

class LogStreamBug : public LogStream {
public:
  LogStreamBug(const std::string& file,
               int line,
               __attribute__((unused)) LogType /*unused*/,
               std::ostream& out = std::cerr)
      : LogStream(file, line, LogType::BUG, out) {};
  [[noreturn]] ~LogStreamBug() override;
};

// clang-format off

// Usage examples:
//
//   1. LOG(WARNING) << "this is a " << "warning!"; (this goes to std::cerr)
//   2. LOG(DEBUG, std::cout) << "this is a " << " message.";
//   3. LOG(ERROR, call.loc.source_location(), std::cerr) << "error with location";
//   4. LOG(ERROR, call.loc.source_location(), call.loc.source_context(), std::err) << "error with context";
//
// Note: LogType::DEBUG will prepend __FILE__ and __LINE__ to the debug message.

#define LOGSTREAM_COMMON(...) bpftrace::LogStream(__FILE__, __LINE__, __VA_ARGS__)
#define LOGSTREAM_DEBUG(...) LOGSTREAM_COMMON(__VA_ARGS__)
#define LOGSTREAM_V1(...) LOGSTREAM_COMMON(__VA_ARGS__)
#define LOGSTREAM_HINT(...) LOGSTREAM_COMMON(__VA_ARGS__)
#define LOGSTREAM_WARNING(...) LOGSTREAM_COMMON(__VA_ARGS__)
#define LOGSTREAM_ERROR(...) LOGSTREAM_COMMON(__VA_ARGS__)
#define LOGSTREAM_BUG(...) bpftrace::LogStreamBug(__FILE__, __LINE__, __VA_ARGS__)
// clang-format on

#define LOG(type, ...) LOGSTREAM_##type(bpftrace::LogType::type, ##__VA_ARGS__)

#define DISABLE_LOG(type) bpftrace::Log::get().disable(LogType::type)
#define ENABLE_LOG(type) bpftrace::Log::get().enable(LogType::type)

}; // namespace bpftrace
