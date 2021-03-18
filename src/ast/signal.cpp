#include "signal_bt.h"

#include <algorithm>
#include <map>

namespace bpftrace {

static std::map<std::string, int> signals = {
  { "SIGABRT", SIGABRT },     { "SIGALRM", SIGALRM },   { "SIGBUS", SIGBUS },
  { "SIGCHLD", SIGCHLD },     { "SIGCONT", SIGCONT },   { "SIGFPE", SIGFPE },
  { "SIGHUP", SIGHUP },       { "SIGILL", SIGILL },     { "SIGINT", SIGINT },
  { "SIGKILL", SIGKILL },     { "SIGPIPE", SIGPIPE },   { "SIGPOLL", SIGPOLL },
  { "SIGQUIT", SIGQUIT },     { "SIGSEGV", SIGSEGV },   { "SIGSTOP", SIGSTOP },
  { "SIGSYS", SIGSYS },       { "SIGTERM", SIGTERM },   { "SIGTRAP", SIGTRAP },
  { "SIGTSTP", SIGTSTP },     { "SIGTTIN", SIGTTIN },   { "SIGTTOU", SIGTTOU },
  { "SIGURG", SIGURG },       { "SIGUSR1", SIGUSR1 },   { "SIGUSR2", SIGUSR2 },
  { "SIGVTALRM", SIGVTALRM }, { "SIGWINCH", SIGWINCH }, { "SIGXCPU", SIGXCPU },
  { "SIGXFSZ", SIGXFSZ },
};

int signal_name_to_num(const std::string &signal)
{
  if (signal.empty())
  {
    return -1;
  }

  std::string sig(signal);

  std::for_each(sig.begin(), sig.end(), [](char &c) { c = ::toupper(c); });

  if (sig[0] != 'S')
  {
    sig.insert(0, "SIG");
  }

  auto s = signals.find(sig);
  if (s != signals.end())
    return s->second;
  return -1;
}

} // namespace bpftrace
