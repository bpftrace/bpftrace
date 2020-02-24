#include <algorithm>
#include <fstream>

#include <cerrno>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "lockdown.h"

namespace bpftrace {
namespace lockdown {

static LockdownState from_string(const std::string &s)
{
  if (s == "none")
    return LockdownState::None;
  else if (s == "integrity")
    return LockdownState::Integrity;
  else if (s == "confidentiality")
    return LockdownState::Confidentiality;

  return LockdownState::Unknown;
}

static bool is_ubuntu(void)
{
  // If ubuntu is somewhere in uname it is probably ubuntu
  struct utsname name = {};
  uname(&name);

  std::string version(name.version);

  std::transform(version.begin(),
                 version.end(),
                 version.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  return (version.find("ubuntu") != std::string::npos);
}

static LockdownState read_security_lockdown(void)
{
  std::ifstream file("/sys/kernel/security/lockdown");
  if (file.fail())
    return LockdownState::Unknown;

  // Format: none [integrity] confidentiality
  // read one field at a time, if it starts with [ it's the one we want
  while (!file.fail())
  {
    std::string field;
    file >> field;
    if (field[0] == '[')
      return from_string(field.substr(1, field.length() - 2));
  }
  return LockdownState::Unknown;
}

void emit_warning(std::ostream &out)
{
  // clang-format off
  // these lines are ~80 chars wide in terminal
  out << "Kernel lockdown is enabled and set to 'confidentiality'. Lockdown mode blocks" << std::endl
      << "parts of BPF which makes it impossible for bpftrace to function. Please see " << std::endl
      << "https://github.com/iovisor/bpftrace/blob/master/INSTALL.md#disable-lockdown" << std::endl
      << "for more details on lockdown and how to disable it." << std::endl;
  // clang-format on
}

LockdownState detect(BPFfeature &feature)
{
  // Ubuntu (19.10 at least) ships a lockdown version that fully blocks the bpf
  // syscall
  if (is_ubuntu() && !feature.has_map_array() &&
      !feature.has_helper_probe_read())
  {
    return LockdownState::Confidentiality;
  }

  return read_security_lockdown();
}

} //  namespace lockdown
} //  namespace bpftrace
