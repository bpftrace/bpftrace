#pragma once

#include <csignal>
#include <string>

#include "util/result.h"

namespace bpftrace::util {

class Proc {
public:
  Proc() = default;
  virtual ~Proc() = default;
  Proc(const Proc&) = delete;
  Proc& operator=(const Proc&) = delete;

  // Whether the process is still alive.
  virtual bool is_alive() = 0;

  // Returns the relevant pid being monitored.
  virtual pid_t pid() = 0;

  // Returns a pidfd that can be monitored for process events.
  virtual Result<int> pidfd() = 0;
};

class ChildProc : public Proc {
public:
  // Execute the child process.
  //
  // \param pause If set the child will be paused(stopped) just
  // after `execve`. To resume the child `resume` will have to
  // be called.
  virtual Result<> run(bool pause = false) = 0;

  // Resume a paused child.
  //
  // Only valid when run() has been called with pause=true.
  virtual Result<> resume() = 0;

  // Terminate the child process.
  //
  // \param force Forcefully kill the child (SIGKILL).
  virtual Result<> terminate(bool force = false) = 0;

  // Wait for the child process to exit.
  //
  // \param timeout_ms Optional timeout in milliseconds.
  //   - std::nullopt: block forever
  //   - 0: non-blocking check
  //   - >0: wait up to timeout_ms milliseconds
  //
  // \return true if child has exited, false if still running (timeout).
  virtual Result<bool> wait(std::optional<int> timeout_ms = std::nullopt) = 0;

  // Get child exit code, if any. This should only be called when the child has
  // finished (i.e. when is_alive() returns false).
  //
  // \return The exit code of the child or -1 if the child hasn't been
  // terminated (by a signal).
  //
  std::optional<int> exit_code()
  {
    return exit_code_;
  };

  // Get termination signal, if any. This should only be called when the child
  // has finished (i.e. when is_alive() returns false).
  //
  // \return A signal ID or -1 if the child hasn't been terminated (by a signal).
  std::optional<int> term_signal()
  {
    return term_signal_;
  };

protected:
  std::optional<int> exit_code_;
  std::optional<int> term_signal_;
};

// Create a concrete implement of Proc, for some external process.
Result<std::unique_ptr<Proc>> create_proc(pid_t pid);

// Create a concrete implementation of ChildProc.
Result<std::unique_ptr<ChildProc>> create_child(const std::string &cmd, bool suppress_stdio = false);

} // namespace bpftrace::util
