#include <cassert>
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <string>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_set>

#include "util/fd.h"
#include "util/paths.h"
#include "util/proc.h"
#include "util/strings.h"

namespace bpftrace::util {

namespace {
class ProcImpl : public Proc {
public:
  ProcImpl(pid_t pid, util::FD pidfd) : pid_(pid), pidfd_(std::move(pidfd)) {};

  bool is_alive() override;
  pid_t pid() override
  {
    return pid_;
  }
  Result<int> pidfd() override
  {
    return pidfd_.get();
  }

private:
  pid_t pid_;
  util::FD pidfd_;
};

class ChildProcImpl : public ChildProc {
public:
  ChildProcImpl(pid_t child_pid,
                util::FD pidfd,
                util::FD&& command_fd,
                util::FD&& result_fd)
      : child_pid_(child_pid),
        pidfd_(std::move(pidfd)),
        command_fd_(std::move(command_fd)),
        result_fd_(std::move(result_fd)) {};

  // Parse command and fork a child process. The child is run with the same
  // permissions and environment variables as bpftrace.
  //
  // \param the command to run, with up to 255 optional arguments. If the
  //   executables path isn't fully specified it the current PATH will be
  //   searched. If more than one binary with the same name is found in the PATH
  //   an exception is raised.
  //
  ChildProcImpl(std::string cmd);
  ~ChildProcImpl() override;

  Result<> run(bool pause = false) override;
  Result<> resume() override;
  Result<> terminate(bool force = false) override;
  Result<bool> wait(std::optional<int> timeout_ms = std::nullopt) override;
  bool is_alive() override;
  pid_t pid() override
  {
    return child_pid_;
  }
  Result<int> pidfd() override
  {
    return pidfd_.get();
  }

  struct Args {
    pid_t orig_parent;
    const char* binary;
    char* const* argv;
    int command_fd;
    int result_fd;
    bool suppress_stdio;
  };
  static int childfn(void* arg);

private:
  enum State {
    Running,
    Stopped,
    PtraceExecStopped,
    Exited,
  };
  Result<State> wait_once(bool block);
  Result<> wait_until(State state);

  pid_t child_pid_;
  util::FD pidfd_;
  util::FD command_fd_;
  util::FD result_fd_;
};
} // namespace

bool ProcImpl::is_alive()
{
  return kill(pid_, 0) == 0;
}

enum Command {
  Go,
  Ptrace,
};

static const char pr_set_pdeathsig_msg[] = "pr_set_pdeathsig() failed";
static const char failed_event_msg[] = "failed to read event fd";
static const char traceme_msg[] = "child: ptrace(traceme) failed";
static const char stop_msg[] = "child: failed to stop";
static const char execve_msg[] = "child: failed to execve";

int ChildProcImpl::childfn(void* arg)
{
  auto* args = static_cast<struct Args*>(arg);

  // Receive SIGTERM if parent dies.
  if (prctl(PR_SET_PDEATHSIG, SIGTERM)) {
    write(args->result_fd,
          pr_set_pdeathsig_msg,
          sizeof(pr_set_pdeathsig_msg) - 1);
    return 1;
  }

  // Check for a race with the parent ahead of the prctl. This
  // means that our parent has exited between the fork and the
  // prctl above, and we should probably exit too.
  if (getppid() != args->orig_parent) {
    return 1;
  }

  // Perform our initial dance.
  Command command;
  if (read(args->command_fd, &command, sizeof(command)) < 0) {
    int err = errno;
    write(args->result_fd, failed_event_msg, sizeof(failed_event_msg) - 1);
    return err;
  }
  switch (command) {
    case Go:
      break;
    case Ptrace:
      if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
        int err = errno;
        write(args->result_fd, traceme_msg, sizeof(traceme_msg) - 1);
        return err;
      }
      if (kill(getpid(), SIGSTOP) < 0) {
        int err = errno;
        write(args->result_fd, stop_msg, sizeof(stop_msg) - 1);
        return -err;
      }
      break;
  }

  // Should we silence errors?
  if (args->suppress_stdio) {
    int null = open("/dev/null", O_RDONLY);
    if (null >= 0) {
      dup2(null, 0);
      close(null);
    }
    null = open("/dev/null", O_WRONLY);
    if (null >= 0) {
      dup2(null, 1);
      dup2(null, 2);
      close(null);
    }
  }

  // N.B. both command_fd and result_fd must be marked as CLO_EXEC,
  // and therefore the successful execve here will close the result
  // and allow the parent to interpret subsequent errors as actual
  // binary failures, rather than failures of this stub section.
  execve(args->binary, args->argv, environ);
  int err = errno;
  write(args->result_fd, execve_msg, sizeof(execve_msg) - 1);
  return err;
}

ChildProcImpl::~ChildProcImpl()
{
  if (!exit_code_ && !term_signal_) {
    auto ok = terminate(true);
    if (!ok) {
      // Nothing can be done; just ignore.
      consumeError(std::move(ok));
    }
  }
}

Result<> ChildProcImpl::terminate(bool force)
{
  if (!force) {
    if (kill(child_pid_, SIGTERM) < 0) {
      return make_error<SystemError>("Unable to terminate child");
    }
    // If child is being traced and stopped, then we need to resume
    // the child to ensure that it is actually able to terminate.
    ptrace(PTRACE_CONT, child_pid_, nullptr, SIGTERM);
  } else {
    if (kill(child_pid_, SIGKILL) < 0) {
      return make_error<SystemError>("Unable to kill child");
    }
  }
  return wait_until(Exited);
}

bool ChildProcImpl::is_alive()
{
  // If already exited, return immediately.
  if (exit_code_.has_value() || term_signal_.has_value()) {
    return false;
  }

  auto ok = wait_once(false);
  return ok && *ok != Exited;
}

Result<bool> ChildProcImpl::wait(std::optional<int> timeout_ms)
{
  // See `is_alive`, check if already exited.
  if (exit_code_.has_value() || term_signal_.has_value()) {
    return true;
  }

  // Blocking wait - use existing wait_until.
  if (!timeout_ms.has_value()) {
    auto ok = wait_until(Exited);
    if (!ok) {
      return ok.takeError();
    }
    return true;
  }

  // Use poll on pidfd with timeout.
  struct pollfd pfd = { .fd = pidfd_.get(), .events = POLLIN, .revents = 0 };
  int ret = poll(&pfd, 1, *timeout_ms);
  if (ret < 0) {
    return make_error<SystemError>("poll failed");
  }
  if (ret == 0) {
    // Timeout - child still running.
    return false;
  }

  // pidfd signaled - reap the child.
  auto state = wait_once(false);
  if (!state) {
    return state.takeError();
  }
  return *state == Exited;
}

Result<> ChildProcImpl::resume()
{
  if (ptrace(PTRACE_DETACH, child_pid_, nullptr, 0) < 0) {
    return make_error<SystemError>("Unable to resume; was the child traced?");
  }
  return OK();
}

Result<> ChildProcImpl::run(bool pause)
{
  // Helper to check result_fd for child errors.
  // Returns OK if child exec'd successfully, or an error with the message.
  auto check_result = [this]() -> Result<> {
    struct pollfd pfd = { .fd = result_fd_.get(),
                          .events = POLLIN,
                          .revents = 0 };
    int ret = poll(&pfd, 1, -1);
    if (ret < 0) {
      return make_error<SystemError>("Poll on result_fd failed");
    }
    char buf[256] = {};
    // Success is defined by having the result pipe closed by exec.
    ssize_t n = read(result_fd_.get(), buf, sizeof(buf) - 1);
    if (n < 0) {
      return make_error<SystemError>("Unexpected failure on result pipe");
    }
    if (n > 0) {
      return make_error<SystemError>(
          std::string(static_cast<const char*>(buf), n), 0);
    }
    return OK();
  };

  // Write our command to the command pipe.
  Command bf = pause ? Ptrace : Go;
  if (write(command_fd_.get(), &bf, sizeof(bf)) < 0) {
    return make_error<SystemError>(
        "Unable to write to command pipe; is the child already running?");
  }

  // For non-pause mode, wait for exec or error, then we're done.
  if (!pause) {
    return check_result();
  }

  // After receiving the ptrace message the child will setup
  // ptrace and SIGSTOP itself. Wait for the child to stop.
  auto ok = wait_until(State::Stopped);
  if (!ok) {
    return ok.takeError();
  }

  // Setup ptrace options and continue.
  if (ptrace(PTRACE_SETOPTIONS, child_pid_, nullptr, PTRACE_O_TRACEEXEC) < 0)
    return make_error<SystemError>("Failed to PTRACE_SETOPTIONS child");
  if (ptrace(PTRACE_CONT, child_pid_, nullptr, 0) < 0)
    return make_error<SystemError>("Failed to PTRACE_CONT child");

  // Wait for the execve event.
  ok = wait_until(State::PtraceExecStopped);
  if (!ok) {
    return ok.takeError();
  }
  return OK();
}

Result<ChildProcImpl::State> ChildProcImpl::wait_once(bool block)
{
  while (true) {
    int status = 0;
    int flags = block ? 0 : WNOHANG;
    pid_t ret = waitpid(child_pid_, &status, flags);
    if (ret < 0) {
      if (errno == EINTR) {
        continue;
      } else if (errno == ECHILD) {
        return make_error<SystemError>("Child does not exist");
      } else {
        return make_error<SystemError>("Unexpected waitpid error");
      }
    }
    if (ret == 0) {
      // There is no work to be done, or we were called with !block
      // and there is no child ready to be waited.
      return Running;
    }
    if (WIFSTOPPED(status)) {
      if (WSTOPSIG(status) == SIGSTOP) {
        return Stopped;
      } else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
        return PtraceExecStopped;
      } else {
        // Signal-delivery-stop: forward the signal so it gets delivered.
        int sig = WSTOPSIG(status);
        if (ptrace(PTRACE_CONT, child_pid_, nullptr, sig) < 0) {
          return make_error<SystemError>("Failed to PTRACE_CONT child");
        }
        continue; // Continue waiting.
      }
    } else if (WIFEXITED(status)) {
      exit_code_.emplace(WEXITSTATUS(status));
      return Exited;
    } else if (WIFSIGNALED(status)) {
      term_signal_.emplace(WTERMSIG(status));
      return Exited;
    } else {
      // The status here is either continue or stopped, which we
      // just ignore unless we are blocking. If we are blocking,
      // then we wait for the proper exit signal to come through.
      if (block) {
        continue;
      } else {
        return Running;
      }
    }
  }
}

Result<> ChildProcImpl::wait_until(State state)
{
  while (true) {
    auto res = wait_once(true);
    if (!res) {
      return res.takeError();
    }
    if (*res == state) {
      return OK();
    }
    if (*res == Exited && state == Stopped) {
      return make_error<SystemError>("Child exited unexpectedly");
    }
  }
}

static Result<std::string> extract_binary(std::vector<std::string>& cmd)
{
  if (cmd.empty()) {
    return make_error<SystemError>("Empty command", ENOENT);
  }
  auto paths = util::resolve_binary_path(cmd[0]);
  switch (paths.size()) {
    case 0:
      return make_error<SystemError>(
          "Path '" + cmd[0] + "' does not exist or is not executable", ENOENT);
    case 1:
      return paths.front();
    default:
      // /bin maybe is a symbolic link to /usr/bin (/bin -> /usr/bin), there
      // may be worse cases like:
      // $ realpath /usr/bin/ping /bin/ping /usr/sbin/ping /sbin/ping
      // /usr/bin/ping
      // /usr/bin/ping
      // /usr/bin/ping
      // /usr/bin/ping
      std::unordered_set<std::string> uniq_abs_path;
      for (const auto& path : paths) {
        auto absolute = util::abs_path(path);
        if (!absolute.has_value())
          continue;
        uniq_abs_path.insert(*absolute);
      }
      if (uniq_abs_path.size() == 1) {
        return paths.front();
      } else {
        return make_error<SystemError>(
            "Path '" + cmd[0] + "' must refer to a unique binary but matched " +
            std::to_string(paths.size()) + " binaries");
      }
  }
}

Result<std::unique_ptr<Proc>> create_proc(pid_t pid)
{
  int fd = syscall(__NR_pidfd_open, pid, 0);
  if (fd < 0) {
    return make_error<SystemError>("Unable to open pidfd");
  }
  return std::unique_ptr<Proc>(new ProcImpl(pid, util::FD(fd)));
}

Result<std::unique_ptr<ChildProc>> create_child(const std::string& cmd,
                                                bool suppress_stdio)
{
  // Create our pipes for both the command and result descriptors.
  int command_fds[2], result_fds[2];
  if (pipe2(command_fds, O_CLOEXEC) < 0) {
    return make_error<SystemError>("Unable to create command pipe");
  }
  if (pipe2(result_fds, O_CLOEXEC) < 0) {
    return make_error<SystemError>("Unable to create result pipe");
  }

  // Construct our arguments for the child.
  auto args = util::split_string(cmd, ' ');
  auto binary = extract_binary(args);
  if (!binary) {
    return binary.takeError();
  }
  std::vector<char*> argv;
  for (auto& arg : args) {
    argv.push_back(const_cast<char*>(arg.c_str()));
  }
  argv.push_back(nullptr);
  ChildProcImpl::Args child_args = {
    .orig_parent = getpid(),
    .binary = binary->c_str(),
    .argv = argv.data(),
    .command_fd = command_fds[0],
    .result_fd = result_fds[1],
    .suppress_stdio = suppress_stdio,
  };

  // Fork the child process.
  constexpr unsigned int STACK_SIZE = (64 * 1024UL);
  auto child_stack = std::make_unique<char[]>(STACK_SIZE);
  pid_t child_pid = clone(ChildProcImpl::childfn,
                          child_stack.get() + STACK_SIZE,
                          SIGCHLD,
                          &child_args);
  close(command_fds[0]);
  close(result_fds[1]);
  util::FD command_fd(command_fds[1]);
  util::FD result_fd(result_fds[0]);
  if (child_pid < 0) {
    return make_error<SystemError>("Unable to fork child process");
  }

  // Bind a pidfd to the child.
  int pidfd = syscall(__NR_pidfd_open, child_pid, 0);
  if (pidfd < 0) {
    return make_error<SystemError>("Unable to open pidfd");
  }

  // Return our object, which will be responsible for the initial run.
  return std::unique_ptr<ChildProc>(new ChildProcImpl(
      child_pid, util::FD(pidfd), std::move(command_fd), std::move(result_fd)));
}

} // namespace bpftrace::util
