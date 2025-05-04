#include "ast/async_event_types.h"
#include "bpftrace.h"
#include "log.h"
#include <memory>
#include <string>

namespace bpftrace::async_action {

const static size_t MAX_TIME_STR_LEN = 64;

void join_handler(BPFtrace *bpftrace, void *data)
{
  auto *join = static_cast<AsyncEvent::Join *>(data);
  uint64_t join_id = join->join_id;
  const auto *delim = bpftrace->resources.join_args[join_id].c_str();
  std::stringstream joined;
  for (unsigned int i = 0; i < bpftrace->join_argnum_; i++) {
    auto *arg = join->content + (i * bpftrace->join_argsize_);
    if (arg[0] == 0)
      break;
    if (i)
      joined << delim;
    joined << arg;
  }
  bpftrace->out_->message(MessageType::join, joined.str());
}

void time_handler(BPFtrace *bpftrace, void *data)
{
  // not respecting config_->get(ConfigKeyInt::max_strlen)
  char timestr[MAX_TIME_STR_LEN];
  time_t t;
  struct tm tmp;
  t = time(nullptr);
  if (!localtime_r(&t, &tmp)) {
    LOG(WARNING) << "localtime_r: " << strerror(errno);
    return;
  }
  auto *time = static_cast<AsyncEvent::Time *>(data);
  const auto *fmt = bpftrace->resources.time_args[time->time_id].c_str();
  if (strftime(timestr, sizeof(timestr), fmt, &tmp) == 0) {
    LOG(WARNING) << "strftime returned 0";
    return;
  }
  bpftrace->out_->message(MessageType::time, timestr, false);
}

void helper_error_handler(BPFtrace *bpftrace, void *data)
{
  auto *helper_error = static_cast<AsyncEvent::HelperError *>(data);
  auto error_id = helper_error->error_id;
  auto return_value = helper_error->return_value;
  auto &info = bpftrace->resources.helper_error_info[error_id];
  bpftrace->out_->helper_error(return_value, info);
}

} // namespace bpftrace::async_action
