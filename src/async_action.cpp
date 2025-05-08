#include "ast/async_event_types.h"
#include "bpftrace.h"
#include "log.h"
#include "util/exceptions.h"
#include "util/io.h"
#include "util/system.h"
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

void syscall_handler(BPFtrace *bpftrace,
                     AsyncAction printf_id,
                     uint8_t *arg_data)
{
  if (bpftrace->safe_mode_) {
    throw util::FatalUserException(
        "syscall() not allowed in safe mode. Use '--unsafe'.");
  }

  auto id = static_cast<uint64_t>(printf_id) -
            static_cast<uint64_t>(AsyncAction::syscall);
  auto &fmt = std::get<0>(bpftrace->resources.system_args[id]);
  auto &args = std::get<1>(bpftrace->resources.system_args[id]);
  auto arg_values = bpftrace->get_arg_values(args, arg_data);

  bpftrace->out_->message(MessageType::syscall,
                          util::exec_system(fmt.format_str(arg_values).c_str()),
                          false);
}

void cat_handler(BPFtrace *bpftrace, AsyncAction printf_id, uint8_t *arg_data)
{
  auto id = static_cast<size_t>(printf_id) -
            static_cast<size_t>(AsyncAction::cat);
  auto &fmt = std::get<0>(bpftrace->resources.cat_args[id]);
  auto &args = std::get<1>(bpftrace->resources.cat_args[id]);
  auto arg_values = bpftrace->get_arg_values(args, arg_data);

  std::stringstream buf;
  util::cat_file(fmt.format_str(arg_values).c_str(),
                 bpftrace->config_->max_cat_bytes,
                 buf);
  bpftrace->out_->message(MessageType::cat, buf.str(), false);
}

} // namespace bpftrace::async_action
