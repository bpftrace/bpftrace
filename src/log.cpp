#include "log.h"

#include <utility>

namespace bpftrace {

static std::string logtype_str(LogType t)
{
  switch (t) {
      // clang-format off
    case LogType::DEBUG   : return "";
    case LogType::V1      : return "";
    case LogType::HINT    : return "HINT: ";
    case LogType::WARNING : return "WARNING: ";
    case LogType::ERROR   : return "ERROR: ";
    case LogType::BUG     : return "BUG: ";
      // clang-format on
  }

  return {}; // unreached
}

Log::Log()
{
  enabled_map_[LogType::DEBUG] = true;
  enabled_map_[LogType::V1] = false;
  enabled_map_[LogType::HINT] = true;
  enabled_map_[LogType::WARNING] = true;
  enabled_map_[LogType::ERROR] = true;
  enabled_map_[LogType::BUG] = true;
}

Log& Log::get()
{
  static Log log;
  return log;
}

void Log::take_input(LogType type,
                     std::optional<std::string>&& source_location,
                     std::optional<std::vector<std::string>>&& source_context,
                     std::ostream& out,
                     std::string&& msg)
{
  if (!msg.empty() && msg.back() == '\n') {
    msg.pop_back();
  }

  const char* color_begin = LogColor::DEFAULT;
  const char* color_end = LogColor::DEFAULT;
  if (is_colorize_) {
    switch (type) {
      case LogType::ERROR:
        color_begin = LogColor::RED;
        color_end = LogColor::RESET;
        break;
      case LogType::WARNING:
        color_begin = LogColor::YELLOW;
        color_end = LogColor::RESET;
        break;
      default:
        break;
    }
  }
  out << color_begin;
  if (source_location) {
    out << *source_location << ": ";
  }
  const std::string& typestr = logtype_str(type);
  out << typestr << msg << color_end << std::endl;

  if (source_context) {
    for (const auto& s : *source_context) {
      out << s << std::endl;
    }
  }
}

LogStream::LogStream(const std::string& file,
                     int line,
                     LogType type,
                     std::ostream& out)
    : file_(file), line_(line), type_(type), out_(out)
{
}

LogStream::LogStream(const std::string& file,
                     int line,
                     LogType type,
                     std::string&& source_location,
                     std::ostream& out)
    : file_(file),
      line_(line),
      type_(type),
      source_location_(std::move(source_location)),
      out_(out)
{
}

LogStream::LogStream(const std::string& file,
                     int line,
                     LogType type,
                     std::string&& source_location,
                     std::vector<std::string>&& source_context,
                     std::ostream& out)
    : file_(file),
      line_(line),
      type_(type),
      source_location_(std::move(source_location)),
      source_context_(std::move(source_context)),
      out_(out)
{
}

LogStream::~LogStream()
{
  auto& sink = Log::get();
  if (sink.is_enabled(type_)) {
    auto msg = buf_.str();
    if (type_ == LogType::DEBUG)
      msg = internal_location() + msg;
    // Pass ownership of all the things to the sink itself, which will evaluate
    // what's available and what's not.
    sink.take_input(type_,
                    std::move(source_location_),
                    std::move(source_context_),
                    out_,
                    std::move(msg));
  }
}

std::string LogStream::internal_location()
{
  std::ostringstream ss;
  ss << "[" << file_ << ":" << line_ << "] ";
  return ss.str();
}

[[noreturn]] LogStreamBug::~LogStreamBug()
{
  auto& sink = Log::get();
  sink.take_input(type_,
                  std::nullopt,
                  std::nullopt,
                  out_,
                  internal_location() + buf_.str());
  abort();
}

}; // namespace bpftrace
