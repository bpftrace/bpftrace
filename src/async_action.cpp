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

void exit_handler(BPFtrace &bpftrace, void *data)
{
  auto *exit = static_cast<AsyncEvent::Exit *>(data);
  BPFtrace::exit_code = exit->exit_code;
  bpftrace.request_finalize();
}

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

void zero_map_handler(BPFtrace &bpftrace, void *data)
{
  auto *mapevent = static_cast<AsyncEvent::MapEvent *>(data);
  const auto &map = bpftrace.bytecode_.getMap(mapevent->mapid);

  auto err = bpftrace.zero_map(map);
  if (err)
    LOG(BUG) << "Could not zero map with ident \"" << map.name()
             << "\", err=" << std::to_string(err);
}

void clear_map_handler(BPFtrace &bpftrace, void *data)
{
  auto *mapevent = static_cast<AsyncEvent::MapEvent *>(data);
  const auto &map = bpftrace.bytecode_.getMap(mapevent->mapid);

  auto err = bpftrace.clear_map(map);
  if (err)
    LOG(BUG) << "Could not clear map with ident \"" << map.name()
             << "\", err=" << std::to_string(err);
}

void watchpoint_attach_handler(BPFtrace &bpftrace, Output &output, void *data)
{
  auto *watchpoint = static_cast<AsyncEvent::Watchpoint *>(data);
  uint64_t probe_idx = watchpoint->watchpoint_idx;
  uint64_t addr = watchpoint->addr;

  if (probe_idx >= bpftrace.resources.watchpoint_probes.size()) {
    LOG(BUG) << "Invalid watchpoint probe idx=" << probe_idx;
  }

  // Ignore duplicate watchpoints (idx && addr same), but allow the same
  // address to be watched by different probes.
  //
  // NB: this check works b/c we set Probe::addr below
  //
  // TODO: Should we be printing a warning or info message out here?
  if (bpftrace.resources.watchpoint_probes[probe_idx].address == addr)
    goto out;

  // Attach the real watchpoint probe
  {
    bool registers_available = true;
    Probe &wp_probe = bpftrace.resources.watchpoint_probes[probe_idx];
    wp_probe.address = addr;
    std::vector<std::unique_ptr<AttachedProbe>> aps;
    try {
      aps = bpftrace.attach_probe(wp_probe, bpftrace.bytecode_);
    } catch (const util::EnospcException &ex) {
      registers_available = false;
      output.message(MessageType::lost_events,
                     "Failed to attach watchpoint probe. You are "
                     "out of watchpoint registers.");
      goto out;
    }

    if (aps.empty() && registers_available) {
      throw util::FatalUserException("Unable to attach real watchpoint probe");
    }

    for (auto &ap : aps)
      bpftrace.attached_probes_.emplace_back(std::move(ap));
  }

out:
  // Async watchpoints are not SIGSTOP'd
  if (bpftrace.resources.watchpoint_probes[probe_idx].async)
    return;
  // Let the tracee continue
  pid_t pid = bpftrace.child_
                  ? bpftrace.child_->pid()
                  : (bpftrace.procmon_ ? bpftrace.procmon_->pid() : -1);
  if (pid == -1 || bpftrace.resume_tracee(pid) != 0) {
    throw util::FatalUserException(
        "Failed to SIGCONT tracee (pid: " + std::to_string(pid) +
        "): " + strerror(errno));
  }
}

void watchpoint_detach_handler(BPFtrace &bpftrace, void *data)
{
  auto *unwatch = static_cast<AsyncEvent::WatchpointUnwatch *>(data);
  uint64_t addr = unwatch->addr;

  // Remove all probes watching `addr`. Note how we fail silently here
  // (ie invalid addr). This lets script writers be a bit more aggressive
  // when unwatch'ing addresses, especially if they're sampling a portion
  // of addresses they're interested in watching.
  auto it = std::ranges::remove_if(bpftrace.attached_probes_,
                                   [&](const auto &ap) {
                                     return ap->probe().address == addr;
                                   });
  bpftrace.attached_probes_.erase(it.begin(), it.end());
}

void skboutput_handler(BPFtrace &bpftrace, void *data, int size)
{
  struct hdr_t {
    uint64_t aid;
    uint64_t id;
    uint64_t ns;
    uint8_t pkt[];
  } __attribute__((packed)) * hdr;

  hdr = static_cast<struct hdr_t *>(data);

  int offset = std::get<1>(bpftrace.resources.skboutput_args_.at(hdr->id));

  bpftrace.write_pcaps(
      hdr->id, hdr->ns, hdr->pkt + offset, size - sizeof(*hdr));
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
