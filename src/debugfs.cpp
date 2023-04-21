#include "debugfs.h"
#include <unistd.h>

namespace bpftrace {
namespace debugfs {

#define DEBUGFS "/sys/kernel/debug"

std::string path()
{
  return DEBUGFS;
}

std::string path(const std::string &file)
{
  return path() + "/" + file;
}

} // namespace debugfs
} // namespace bpftrace
