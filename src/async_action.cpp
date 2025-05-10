#include <memory>
#include <string>

#include "ast/async_event_types.h"
#include "async_action.h"
#include "bpftrace.h"
#include "log.h"
#include "util/exceptions.h"
#include "util/io.h"
#include "util/system.h"

namespace bpftrace::async_action {

void join_handler(BPFtrace &bpftrace, Output &out, void *data)
{
  auto *join = static_cast<AsyncEvent::Join *>(data);
  uint64_t join_id = join->join_id;
  const auto *delim = bpftrace.resources.join_args[join_id].c_str();
  std::stringstream joined;
  for (unsigned int i = 0; i < bpftrace.join_argnum_; i++) {
    auto *arg = join->content + (i * bpftrace.join_argsize_);
    if (arg[0] == 0)
      break;
    if (i)
      joined << delim;
    joined << arg;
  }
  out.message(MessageType::join, joined.str());
}

void time_handler(BPFtrace &bpftrace, Output &out, void *data)
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
  const auto *fmt = bpftrace.resources.time_args[time->time_id].c_str();
  if (strftime(timestr, sizeof(timestr), fmt, &tmp) == 0) {
    LOG(WARNING) << "strftime returned 0";
    return;
  }
  out.message(MessageType::time, timestr, false);
}

void helper_error_handler(BPFtrace &bpftrace, Output &out, void *data)
{
  auto *helper_error = static_cast<AsyncEvent::HelperError *>(data);
  auto error_id = helper_error->error_id;
  auto return_value = helper_error->return_value;
  auto &info = bpftrace.resources.helper_error_info[error_id];
  out.helper_error(return_value, info);
}

void print_non_map_handler(BPFtrace &bpftrace, Output &out, void *data)
{
  auto *print = static_cast<AsyncEvent::PrintNonMap *>(data);
  const SizedType &ty = bpftrace.resources.non_map_print_args.at(
      print->print_id);

  std::vector<uint8_t> bytes;
  for (size_t i = 0; i < ty.GetSize(); ++i)
    bytes.emplace_back(print->content[i]);

  out.value(bpftrace, ty, bytes);
}

void syscall_handler(BPFtrace &bpftrace,
                     Output &out,
                     AsyncAction printf_id,
                     uint8_t *arg_data)
{
  if (bpftrace.safe_mode_) {
    throw util::FatalUserException(
        "syscall() not allowed in safe mode. Use '--unsafe'.");
  }

  auto id = static_cast<uint64_t>(printf_id) -
            static_cast<uint64_t>(AsyncAction::syscall);
  auto &fmt = std::get<0>(bpftrace.resources.system_args[id]);
  auto &args = std::get<1>(bpftrace.resources.system_args[id]);
  auto arg_values = bpftrace.get_arg_values(out, args, arg_data);

  out.message(MessageType::syscall,
              util::exec_system(fmt.format_str(arg_values).c_str()),
              false);
}

void cat_handler(BPFtrace &bpftrace,
                 Output &out,
                 AsyncAction printf_id,
                 uint8_t *arg_data)
{
  auto id = static_cast<size_t>(printf_id) -
            static_cast<size_t>(AsyncAction::cat);
  auto &fmt = std::get<0>(bpftrace.resources.cat_args[id]);
  auto &args = std::get<1>(bpftrace.resources.cat_args[id]);
  auto arg_values = bpftrace.get_arg_values(out, args, arg_data);

  std::stringstream buf;
  util::cat_file(fmt.format_str(arg_values).c_str(),
                 bpftrace.config_->max_cat_bytes,
                 buf);
  out.message(MessageType::cat, buf.str(), false);
}

void printf_handler(BPFtrace &bpftrace,
                    Output &out,
                    AsyncAction printf_id,
                    uint8_t *arg_data)
{
  auto id = static_cast<size_t>(printf_id) -
            static_cast<size_t>(AsyncAction::printf);
  auto &fmt = std::get<0>(bpftrace.resources.printf_args[id]);
  auto &args = std::get<1>(bpftrace.resources.printf_args[id]);
  auto arg_values = bpftrace.get_arg_values(out, args, arg_data);

  out.message(MessageType::printf, fmt.format_str(arg_values), false);
}

} // namespace bpftrace::async_action
