#include "tracefs.h"
#include <unistd.h>

namespace bpftrace::tracefs {

#define DEBUGFS_TRACEFS "/sys/kernel/debug/tracing"
#define TRACEFS "/sys/kernel/tracing"

std::string path()
{
  static bool use_debugfs = access(DEBUGFS_TRACEFS, F_OK) == 0;
  return use_debugfs ? DEBUGFS_TRACEFS : TRACEFS;
}

std::string path(const std::string &file)
{
  return path() + "/" + file;
}

std::string event_format_file(const std::string &category,
                              const std::string &event)
{
  return path("events/" + category + "/" + event + "/format");
}

} // namespace bpftrace::tracefs
