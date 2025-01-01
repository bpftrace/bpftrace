#include <csignal>

#include "log.h"
#include "run_bpftrace.h"

using namespace bpftrace;

static const char *libbpf_print_level_string(enum libbpf_print_level level)
{
  switch (level) {
    case LIBBPF_WARN:
      return "WARN";
    case LIBBPF_INFO:
      return "INFO";
    default:
      return "DEBUG";
  }
}

int libbpf_print(enum libbpf_print_level level, const char *msg, va_list ap)
{
  if (bt_debug.find(DebugStage::Libbpf) == bt_debug.end())
    return 0;

  printf("[%s] ", libbpf_print_level_string(level));
  return vprintf(msg, ap);
}

void check_is_root()
{
  if (geteuid() != 0) {
    LOG(ERROR) << "bpftrace currently only supports running as the root user.";
    exit(1);
  }
}

int run_bpftrace(BPFtrace &bpftrace, BpfBytecode &bytecode)
{
  int err;

  // Signal handler that lets us know an exit signal was received.
  struct sigaction act = {};
  act.sa_handler = [](int) { BPFtrace::exitsig_recv = true; };
  sigaction(SIGINT, &act, nullptr);
  sigaction(SIGTERM, &act, nullptr);

  // Signal handler that prints all maps when SIGUSR1 was received.
  act.sa_handler = [](int) { BPFtrace::sigusr1_recv = true; };
  sigaction(SIGUSR1, &act, nullptr);

  err = bpftrace.run(std::move(bytecode));
  if (err)
    return err;

  // We are now post-processing. If we receive another SIGINT,
  // handle it normally (exit)
  act.sa_handler = SIG_DFL;
  sigaction(SIGINT, &act, nullptr);

  std::cout << "\n\n";

  // Print maps if needed (true by default).
  if (bpftrace.config_.get(ConfigKeyBool::print_maps_on_exit))
    err = bpftrace.print_maps();

  if (bpftrace.child_) {
    auto val = 0;
    if ((val = bpftrace.child_->term_signal()) > -1)
      LOG(V1) << "Child terminated by signal: " << val;
    if ((val = bpftrace.child_->exit_code()) > -1)
      LOG(V1) << "Child exited with code: " << val;
  }

  if (err)
    return err;

  return BPFtrace::exit_code;
}
