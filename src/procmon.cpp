#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <stdexcept>
#include <sys/syscall.h>
#include <system_error>
#include <unistd.h>

#include "procmon.h"
#include "utils.h"

namespace bpftrace {

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif

static std::system_error SYS_ERROR(std::string msg)
{
  return std::system_error(errno, std::generic_category(), msg);
}

static inline int pidfd_open(int pid, unsigned int flags)
{
  return syscall(__NR_pidfd_open, pid, flags);
}

ProcMon::ProcMon(const std::string& pid)
{
  setup(parse_pid(pid));
}

ProcMon::ProcMon(pid_t pid)
{
  setup(pid);
}

void ProcMon::setup(pid_t pid)
{
  pid_ = pid;

  int pidfd = pidfd_open(pid, 0);
  // Fall back to polling if pidfds or anon inodes are not supported
  if (pidfd >= 0)
  {
    pidfd_ = pidfd;
    return;
  }
  else if (errno != ENOSYS)
  {
    if (errno == ESRCH)
      throw SYS_ERROR(""); /* use default error message for ESRCH */
    throw SYS_ERROR("Failed to pidfd_open pid");
  }

  int ret = snprintf(proc_path_,
                     sizeof(proc_path_) / sizeof(proc_path_[0]),
                     "/proc/%d/status",
                     pid);
  if (ret < 0)
  {
    throw std::runtime_error("failed to snprintf");
  }

  if (!is_alive())
    throw std::runtime_error("No such process: " + std::to_string(pid));
}

ProcMon::~ProcMon()
{
  if (pidfd_ >= 0)
    close(pidfd_);
}

bool ProcMon::is_alive(void)
{
  // store death to avoid pid reuse issues on polling /proc
  if (died_)
    return false;

  if (pidfd_ > -1)
  {
    struct pollfd pollfd;
    pollfd.fd = pidfd_;
    pollfd.events = POLLIN;

    int ret;
    while ((ret = poll(&pollfd, 1, 0)) < 0 && errno == EINTR)
      ;

    if (ret < 0)
      throw SYS_ERROR("poll pidfd");
    else if (ret == 0) // no change, so must be alive
      return true;

    died_ = true;
    return false;
  }

  int fd = open(proc_path_, 0, O_RDONLY);
  if (fd < 0)
  {
    if (errno == ENOENT)
    {
      died_ = true;
      return false;
    }
    std::string msg = "Failed to open " + std::string(proc_path_);
    throw SYS_ERROR(msg);
  }

  close(fd);
  return true;
}

} // namespace bpftrace
