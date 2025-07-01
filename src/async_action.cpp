#include <memory>
#include <string>

#include "ast/async_event_types.h"
#include "async_action.h"
#include "bpftrace.h"
#include "log.h"
#include "types_format.h"
#include "util/exceptions.h"
#include "util/io.h"
#include "util/system.h"

namespace bpftrace::async_action {

void AsyncHandlers::exit(const void *data)
{
  const auto *exit = static_cast<const AsyncEvent::Exit *>(data);
  BPFtrace::exit_code = exit->exit_code;
  bpftrace.request_finalize();
}

void AsyncHandlers::join(const void *data)
{
  const auto *join = static_cast<const AsyncEvent::Join *>(data);
  uint64_t join_id = join->join_id;
  const auto *delim = bpftrace.resources.join_args[join_id].c_str();
  std::stringstream joined;
  for (unsigned int i = 0; i < bpftrace.join_argnum_; i++) {
    const auto *arg = join->content + (i * bpftrace.join_argsize_);
    if (arg[0] == 0)
      break;
    if (i)
      joined << delim;
    joined << arg;
  }
  out.join(joined.str());
}

void AsyncHandlers::time(const void *data)
{
  // not respecting config_->get(ConfigKeyInt::max_strlen)
  char timestr[AsyncHandlers::MAX_TIME_STR_LEN];
  time_t t;
  struct tm tmp;
  t = ::time(nullptr);
  if (!localtime_r(&t, &tmp)) {
    LOG(WARNING) << "localtime_r: " << strerror(errno);
    return;
  }
  const auto *time = static_cast<const AsyncEvent::Time *>(data);
  const auto *fmt = bpftrace.resources.time_args[time->time_id].c_str();
  if (strftime(timestr, sizeof(timestr), fmt, &tmp) == 0) {
    LOG(WARNING) << "strftime returned 0";
    return;
  }
  out.time(timestr);
}

void AsyncHandlers::helper_error(const void *data)
{
  const auto *helper_error = static_cast<const AsyncEvent::HelperError *>(data);
  auto error_id = helper_error->error_id;
  const auto return_value = helper_error->return_value;
  const auto &info = bpftrace.resources.helper_error_info[error_id];
  out.helper_error(return_value, info);
}

void AsyncHandlers::print_non_map(const void *data)
{
  const auto *print = static_cast<const AsyncEvent::PrintNonMap *>(data);
  const SizedType &ty = bpftrace.resources.non_map_print_args.at(
      print->print_id);

  auto v = format(bpftrace,
                  c_definitions,
                  ty,
                  OpaqueValue::from(print->content, ty.GetSize()));
  if (!v) {
    LOG(BUG) << "error printing non-map value: " << v.takeError();
  }
  out.value(*v);
}

void AsyncHandlers::print_map(const void *data)
{
  const auto *print = static_cast<const AsyncEvent::Print *>(data);
  const auto &map = bpftrace.bytecode_.getMap(print->mapid);

  auto res = format(bpftrace, c_definitions, map, print->top, print->div);
  if (!res) {
    LOG(BUG) << "Could not print map with ident \"" << map.name()
             << "\": " << res.takeError();
  }

  out.map(map.name(), *res);
}

void AsyncHandlers::zero_map(const void *data)
{
  const auto *mapevent = static_cast<const AsyncEvent::MapEvent *>(data);
  const auto &map = bpftrace.bytecode_.getMap(mapevent->mapid);
  uint64_t nvalues = map.is_per_cpu_type() ? bpftrace.ncpus_ : 1;
  auto ok = map.zero_out(nvalues);

  if (!ok) {
    LOG(BUG) << "Could not zero map with ident \"" << map.name()
             << "\", err=" << ok.takeError();
  }
}

void AsyncHandlers::clear_map(const void *data)
{
  const auto *mapevent = static_cast<const AsyncEvent::MapEvent *>(data);
  const auto &map = bpftrace.bytecode_.getMap(mapevent->mapid);
  uint64_t nvalues = map.is_per_cpu_type() ? bpftrace.ncpus_ : 1;
  auto ok = map.clear(nvalues);
  if (!ok) {
    LOG(BUG) << "Could not clear map with ident \"" << map.name()
             << "\", err=" << ok.takeError();
  }
}

void AsyncHandlers::watchpoint_attach(const void *data)
{
  const auto *watchpoint = static_cast<const AsyncEvent::Watchpoint *>(data);
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
    Probe &wp_probe = bpftrace.resources.watchpoint_probes[probe_idx];
    wp_probe.address = addr;

    auto ap = bpftrace.attach_probe(wp_probe, bpftrace.bytecode_);

    if (!ap) {
      if (bpftrace.config_->missing_probes == ConfigMissingProbes::error) {
        throw util::FatalUserException(
            "Unable to attach real watchpoint probe");
      }
    } else {
      bpftrace.attached_probes_.push_back(std::move(*ap));
    }
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

void AsyncHandlers::watchpoint_detach(const void *data)
{
  const auto *unwatch = static_cast<const AsyncEvent::WatchpointUnwatch *>(
      data);
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

void AsyncHandlers::skboutput(void *data, int size)
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

void AsyncHandlers::syscall(AsyncAction printf_id, uint8_t *arg_data)
{
  if (bpftrace.safe_mode_) {
    throw util::FatalUserException(
        "syscall() not allowed in safe mode. Use '--unsafe'.");
  }

  auto id = static_cast<uint64_t>(printf_id) -
            static_cast<uint64_t>(AsyncAction::syscall);
  auto &fmt = std::get<0>(bpftrace.resources.system_args[id]);
  auto &args = std::get<1>(bpftrace.resources.system_args[id]);
  auto arg_values = bpftrace.get_arg_values(c_definitions, args, arg_data);

  out.syscall(util::exec_system(fmt.format_str(arg_values).c_str()));
}

void AsyncHandlers::cat(AsyncAction printf_id, uint8_t *arg_data)
{
  auto id = static_cast<size_t>(printf_id) -
            static_cast<size_t>(AsyncAction::cat);
  auto &fmt = std::get<0>(bpftrace.resources.cat_args[id]);
  auto &args = std::get<1>(bpftrace.resources.cat_args[id]);
  auto arg_values = bpftrace.get_arg_values(c_definitions, args, arg_data);

  std::stringstream buf;
  util::cat_file(fmt.format_str(arg_values).c_str(),
                 bpftrace.config_->max_cat_bytes,
                 buf);
  out.cat(buf.str());
}

void AsyncHandlers::printf(AsyncAction printf_id, uint8_t *arg_data)
{
  auto id = static_cast<size_t>(printf_id) -
            static_cast<size_t>(AsyncAction::printf);
  auto &fmt = std::get<0>(bpftrace.resources.printf_args[id]);
  auto &args = std::get<1>(bpftrace.resources.printf_args[id]);
  auto arg_values = bpftrace.get_arg_values(c_definitions, args, arg_data);

  out.printf(fmt.format_str(arg_values));
}

} // namespace bpftrace::async_action
