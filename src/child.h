#pragma once

#include <csignal>
#include <memory>
#include <string>
#include <vector>

namespace bpftrace {

struct child_args
{
  std::vector<std::string> cmd;
  int event_fd;
};

class ChildProcBase
{
public:
  /**
     Parse command and fork a child process.

     \param cmd Command to run
   */
  ChildProcBase() = default;
  virtual ~ChildProcBase() = default;

  /**
     let child run (execve).

     \param pause If set the child will be paused(stopped) just
     after `execve`. To resume the child `resume` will have to
     be called.
  */
  virtual void run(bool pause = false) = 0;

  /**
     Ask child to terminate

     \param force Forcefully kill the child (SIGKILL)
  */
  virtual void terminate(bool force = false) = 0;

  /**
     Whether the child process is still alive or not
  */
  virtual bool is_alive() = 0;

  /**
     return the child pid
  */
  pid_t pid()
  {
    return child_pid_;
  };

  /**
     Get child exit code, if any. This should only be called when the child has
     finished (i.e. when is_alive() returns false)

     \return The exit code of the child or -1 if the child hasn't been
  terminated (by a signal)

  */
  int exit_code()
  {
    return exit_code_;
  };

  /**
     Get termination signal, if any. This should only be called when the child
     has finished (i.e. when is_alive() returns false)

     \return A signal ID or -1 if the child hasn't been terminated (by a signal)
  */
  int term_signal()
  {
    return term_signal_;
  };

  /**
     Resume a paused child. Only valid when run() has been called with
     pause=true
   */
  virtual void resume(void) = 0;

protected:
  pid_t child_pid_ = -1;
  int exit_code_ = -1;
  int term_signal_ = -1;
};

class ChildProc : public ChildProcBase
{
public:
  /**
    Parse command and fork a child process. The child is run with the same
    permissions and environment variables as bpftrace.

    \param the command to run, with up to 255 optional arguments. If the
  executables path isn't fully specified it the current PATH will be searched.
  If more than one binary with the same name is found in the PATH an exception
  is raised.

  */
  ChildProc(std::string cmd);
  ~ChildProc();

  // Disallow copying as the internal state will get out of sync which will
  // cause issues.
  ChildProc(const ChildProc&) = delete;
  ChildProc& operator=(const ChildProc&) = delete;
  ChildProc(ChildProc&&) = delete;
  ChildProc& operator=(ChildProc&&) = delete;

  void run(bool pause = false) override;
  void terminate(bool force = false) override;
  bool is_alive() override;
  void resume(void) override;

private:
  enum class State
  {
    INIT,
    FORKED,
    RUNNING,
    DIED,
    PTRACE_PAUSE,
  };

  State state_ = State::INIT;

  void check_child(bool block = false);
  void check_wstatus(int wstatus);
  bool died()
  {
    return state_ == State::DIED;
  };

  int child_event_fd_ = -1;
};

} // namespace bpftrace
