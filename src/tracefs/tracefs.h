#pragma once

#include <string>

namespace bpftrace::tracefs {

std::string path();

std::string path(const std::string &file);

inline std::string available_events()
{
  return path("available_events");
}

inline std::string events()
{
  return path("events");
}

std::string event_format_file(const std::string &category,
                              const std::string &event);

} // namespace bpftrace::tracefs
