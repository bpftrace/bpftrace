#pragma once

#include <iostream>
#include <optional>
#include <sstream>

#include "bpftrace.h"

namespace bpftrace {

// clang-format off
enum class LogType
{
  DEBUG,
  INFO,
  WARNING,
  ERROR
};
// clang-format on

class Log
{
public:
  static Log& get();
  void take_input(LogType type,
                  const std::optional<location>& loc,
                  std::ostream& out,
                  std::string&& input);
  inline void set_source(const std::string& filename, const std::string& source)
  {
    src_ = source;
    filename_ = filename;
  }
  inline const std::string& get_source()
  {
    return src_;
  }
  const std::string get_source_line(unsigned int n);

  // Can only construct with get()
  Log(const Log& other) = delete;
  Log& operator=(const Log& other) = delete;

private:
  Log() = default;
  ~Log() = default;
  std::string src_;
  std::string filename_;
  void log_with_location(LogType,
                         const location&,
                         std::ostream&,
                         const std::string&);
};

class LogStream
{
public:
  LogStream(const std::string& file,
            int line,
            LogType type,
            std::ostream& out = std::cerr);
  LogStream(const std::string& file,
            int line,
            LogType type,
            const location& loc,
            std::ostream& out = std::cerr);
  template <typename T>
  LogStream& operator<<(const T& v)
  {
    buf_ << v;
    return *this;
  }
  ~LogStream();

private:
  Log& sink_;
  LogType type_;
  const std::optional<location> loc_;
  std::ostream& out_;
  std::string log_file_;
  int log_line_;
  std::ostringstream buf_;
};

// Usage examples:
// 1. LOG(WARNING) << "this is a " << "warning!"; (this goes to std::cerr)
// 2. LOG(DEBUG, std::cout) << "this is a " << " message.";
// 3. LOG(ERROR, call.loc, std::cerr) << "this is a semantic error";
// Note: LogType::DEBUG will prepend __FILE__ and __LINE__ to the debug message

#define LOG(...) LogStream(__FILE__, __LINE__, LogType::__VA_ARGS__)
}; // namespace bpftrace
