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

void AsyncHandlers::exit(const OpaqueValue &data)
{
  const auto &exit = data.bitcast<AsyncEvent::Exit>();
  BPFtrace::exit_code = exit.exit_code;
  bpftrace.request_finalize();
}

void AsyncHandlers::join(const OpaqueValue &data)
{
  const auto &join = data.bitcast<AsyncEvent::Join>();
  uint64_t join_id = join.join_id;
  const auto *delim = bpftrace.resources.join_args[join_id].c_str();
  auto arg = data.slice(sizeof(AsyncEvent::Join));
  size_t arg_count = arg.count<char>() / bpftrace.join_argsize_;
  std::stringstream joined;
  for (unsigned int i = 0; i < arg_count; i++) {
    if (i)
      joined << delim;
    joined << (arg.data() + (i * bpftrace.join_argsize_));
  }
  out.join(joined.str());
}

void AsyncHandlers::time(const OpaqueValue &data)
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
  const auto &time = data.bitcast<AsyncEvent::Time>();
  const auto *fmt = bpftrace.resources.time_args[time.time_id].c_str();
  if (strftime(timestr, sizeof(timestr), fmt, &tmp) == 0) {
    LOG(WARNING) << "strftime returned 0";
    return;
  }
  out.time(timestr);
}

void AsyncHandlers::runtime_error(const OpaqueValue &data)
{
  const auto &runtime_error = data.bitcast<AsyncEvent::RuntimeError>();
  auto error_id = runtime_error.error_id;
  const auto return_value = runtime_error.return_value;
  const auto &info = bpftrace.resources.runtime_error_info[error_id];
  out.runtime_error(return_value, info);
}

void AsyncHandlers::print_non_map(const OpaqueValue &data)
{
  const auto &print = data.bitcast<AsyncEvent::PrintNonMap>();
  const SizedType &ty = bpftrace.resources.non_map_print_args.at(
      print.print_id);

  auto v = format(bpftrace,
                  c_definitions,
                  ty,
                  OpaqueValue::from(&print.content[0], ty.GetSize()));
  if (!v) {
    LOG(BUG) << "error printing non-map value: " << v.takeError();
  }
  out.value(*v);
}

void AsyncHandlers::print_map(const OpaqueValue &data)
{
  const auto &print = data.bitcast<AsyncEvent::Print>();
  const auto &map = bpftrace.bytecode_.getMap(print.mapid);

  auto res = format(bpftrace, c_definitions, map, print.top, print.div);
  if (!res) {
    LOG(BUG) << "Could not print map with ident \"" << map.name()
             << "\": " << res.takeError();
  }

  out.map(map.name(), *res);
}

void AsyncHandlers::zero_map(const OpaqueValue &data)
{
  const auto &mapevent = data.bitcast<AsyncEvent::MapEvent>();
  const auto &map = bpftrace.bytecode_.getMap(mapevent.mapid);
  uint64_t nvalues = map.is_per_cpu_type() ? bpftrace.ncpus_ : 1;
  auto ok = map.zero_out(nvalues);

  if (!ok) {
    LOG(BUG) << "Could not zero map with ident \"" << map.name()
             << "\", err=" << ok.takeError();
  }
}

void AsyncHandlers::clear_map(const OpaqueValue &data)
{
  const auto &mapevent = data.bitcast<AsyncEvent::MapEvent>();
  const auto &map = bpftrace.bytecode_.getMap(mapevent.mapid);
  uint64_t nvalues = map.is_per_cpu_type() ? bpftrace.ncpus_ : 1;
  auto ok = map.clear(nvalues);
  if (!ok) {
    LOG(BUG) << "Could not clear map with ident \"" << map.name()
             << "\", err=" << ok.takeError();
  }
}

void AsyncHandlers::watchpoint_attach(const OpaqueValue &data)
{
  const auto &watchpoint = data.bitcast<AsyncEvent::Watchpoint>();
  uint64_t probe_idx = watchpoint.watchpoint_idx;
  uint64_t addr = watchpoint.addr;

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

void AsyncHandlers::watchpoint_detach(const OpaqueValue &data)
{
  const auto &unwatch = data.bitcast<AsyncEvent::WatchpointUnwatch>();
  uint64_t addr = unwatch.addr;

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

void AsyncHandlers::skboutput(const OpaqueValue &data)
{
  const auto &hdr = data.bitcast<AsyncEvent::SkbOutput>();
  int offset = std::get<1>(
      bpftrace.resources.skboutput_args_.at(hdr.skb_output_id));
  auto pkt = data.slice(sizeof(hdr));
  if (static_cast<size_t>(offset) >= pkt.size()) {
    return; // Nothing to dump.
  }
  bpftrace.write_pcaps(hdr.skb_output_id,
                       hdr.nsecs_since_boot,
                       pkt.slice(offset));
}

void AsyncHandlers::syscall(const OpaqueValue &data)
{
  if (bpftrace.safe_mode_) {
    throw util::FatalUserException(
        "syscall() not allowed in safe mode. Use '--unsafe'.");
  }

  auto id = data.bitcast<uint64_t>() -
            static_cast<uint64_t>(AsyncAction::syscall);
  auto &fmt = std::get<0>(bpftrace.resources.system_args[id]);
  auto &args = std::get<1>(bpftrace.resources.system_args[id]);
  auto arg_values = bpftrace.get_arg_values(
      c_definitions, args, data.slice(sizeof(uint64_t)).data());

  out.syscall(util::exec_system(fmt.format_str(arg_values).c_str()));
}

void AsyncHandlers::cat(const OpaqueValue &data)
{
  auto id = data.bitcast<uint64_t>() - static_cast<uint64_t>(AsyncAction::cat);
  auto &fmt = std::get<0>(bpftrace.resources.cat_args[id]);
  auto &args = std::get<1>(bpftrace.resources.cat_args[id]);
  auto arg_values = bpftrace.get_arg_values(
      c_definitions, args, data.slice(sizeof(uint64_t)).data());

  std::stringstream buf;
  util::cat_file(fmt.format_str(arg_values).c_str(),
                 bpftrace.config_->max_cat_bytes,
                 buf);
  out.cat(buf.str());
}

void AsyncHandlers::printf(const OpaqueValue &data)
{
  auto id = data.bitcast<uint64_t>() -
            static_cast<uint64_t>(AsyncAction::printf);
  auto &fmt = std::get<0>(bpftrace.resources.printf_args[id]);
  auto &args = std::get<1>(bpftrace.resources.printf_args[id]);
  auto arg_values = bpftrace.get_arg_values(
      c_definitions, args, data.slice(sizeof(uint64_t)).data());
  out.printf(fmt.format_str(arg_values));
}

void AsyncHandlers::print_error(const OpaqueValue &data)
{
  auto id = data.bitcast<uint64_t>() -
            static_cast<uint64_t>(AsyncAction::print_error);
  auto &tuple = bpftrace.resources.print_error_args[id];
  auto &fmt = std::get<0>(tuple);
  auto &args = std::get<1>(tuple);
  auto &errorInfo = std::get<2>(tuple);
  auto arg_values = bpftrace.get_arg_values(
      c_definitions, args, data.slice(sizeof(uint64_t)).data());
  out.print_error(fmt.format_str(arg_values), errorInfo);
}

} // namespace bpftrace::async_action
