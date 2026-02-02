#include <fstream>
#include <memory>
#include <string>

#include "ast/async_event_types.h"
#include "async_action.h"
#include "bpftrace.h"
#include "log.h"
#include "types_format.h"
#include "util/exceptions.h"
#include "util/system.h"

namespace bpftrace::async_action {

static Result<std::vector<output::Primitive>> prepare_args(
    BPFtrace &bpftrace,
    const ast::CDefinitions &c_definitions,
    const std::vector<Field> &fields,
    const OpaqueValue &value)
{
  std::vector<output::Primitive> res;
  for (const auto &field : fields) {
    auto v = format(bpftrace,
                    c_definitions,
                    field.type,
                    value.slice(field.offset, field.type.GetSize()));
    if (!v) {
      return v.takeError();
    }
    res.emplace_back(std::move(*v));
  }
  return res;
}

Result<> AsyncHandlers::exit(const OpaqueValue &data)
{
  auto exit = data.bitcast<AsyncEvent::Exit>();
  bpftrace.exit_code = exit.exit_code;
  bpftrace.request_finalize();
  return OK();
}

Result<> AsyncHandlers::join(const OpaqueValue &data)
{
  auto join = data.bitcast<AsyncEvent::Join>();
  uint64_t join_id = join.join_id;
  const auto *delim = bpftrace.resources.join_args[join_id].c_str();
  auto arg = data.slice(sizeof(AsyncEvent::Join));
  size_t arg_count = arg.count<char>() / bpftrace.join_argsize_;
  std::stringstream joined;
  for (unsigned int i = 0; i < arg_count; i++) {
    const char *current_str = arg.data() + (i * bpftrace.join_argsize_);
    if (current_str == nullptr || current_str[0] == '\0') {
      break;
    }
    if (i)
      joined << delim;
    joined << current_str;
  }
  out->join(joined.str());
  return OK();
}

Result<> AsyncHandlers::time(const OpaqueValue &data)
{
  // not respecting config_->get(ConfigKeyInt::max_strlen)
  char timestr[AsyncHandlers::MAX_TIME_STR_LEN];
  time_t t;
  struct tm tmp;
  t = ::time(nullptr);
  if (!localtime_r(&t, &tmp)) {
    return make_error<SystemError>("unable to get localtime");
  }
  auto time = data.bitcast<AsyncEvent::Time>();
  const auto *fmt = bpftrace.resources.time_args[time.time_id].c_str();
  if (strftime(timestr, sizeof(timestr), fmt, &tmp) == 0) {
    return make_error<SystemError>("strftime returned zero");
  }
  out->time(timestr);
  return OK();
}

Result<> AsyncHandlers::runtime_error(const OpaqueValue &data)
{
  auto runtime_error = data.bitcast<AsyncEvent::RuntimeError>();
  auto error_id = runtime_error.error_id;
  const auto return_value = runtime_error.return_value;
  const auto &info = bpftrace.resources.runtime_error_info[error_id];
  out->runtime_error(return_value, info);
  return OK();
}

Result<> AsyncHandlers::print_non_map(const OpaqueValue &data)
{
  auto print = data.bitcast<AsyncEvent::PrintNonMap>();
  const SizedType &ty = bpftrace.resources.non_map_print_args.at(
      print.print_id);

  auto v = format(
      bpftrace, c_definitions, ty, data.slice(sizeof(AsyncEvent::PrintNonMap)));
  if (!v) {
    return v.takeError();
  }
  out->value(*v);
  return OK();
}

Result<> AsyncHandlers::print_map(const OpaqueValue &data)
{
  auto print = data.bitcast<AsyncEvent::Print>();
  const auto &map = bpftrace.bytecode_.getMap(print.mapid);

  auto res = format(bpftrace, c_definitions, map, print.top, print.div);
  if (!res) {
    return res.takeError();
  }

  out->map(map.name(), *res);
  return OK();
}

Result<> AsyncHandlers::zero_map(const OpaqueValue &data)
{
  auto mapevent = data.bitcast<AsyncEvent::MapEvent>();
  const auto &map = bpftrace.bytecode_.getMap(mapevent.mapid);
  uint64_t nvalues = map.is_per_cpu_type() ? bpftrace.ncpus_ : 1;
  return map.zero_out(nvalues);
}

Result<> AsyncHandlers::clear_map(const OpaqueValue &data)
{
  auto mapevent = data.bitcast<AsyncEvent::MapEvent>();
  const auto &map = bpftrace.bytecode_.getMap(mapevent.mapid);
  return map.clear();
}

Result<> AsyncHandlers::skboutput(const OpaqueValue &data)
{
  auto hdr = data.bitcast<AsyncEvent::SkbOutput>();
  int offset = std::get<1>(
      bpftrace.resources.skboutput_args_.at(hdr.skb_output_id));
  auto pkt = data.slice(sizeof(hdr));
  if (static_cast<size_t>(offset) >= pkt.size()) {
    return OK(); // Nothing to dump.
  }
  bpftrace.write_pcaps(hdr.skb_output_id,
                       hdr.nsecs_since_boot,
                       pkt.slice(offset));
  return OK();
}

Result<> AsyncHandlers::syscall(const OpaqueValue &data)
{
  if (bpftrace.safe_mode_) {
    return make_error<SystemError>(
        "syscall() not allowed in safe mode. Use '--unsafe'.", EPERM);
  }

  auto id = data.bitcast<uint64_t>() -
            static_cast<uint64_t>(AsyncAction::syscall);
  auto &fmt = std::get<0>(bpftrace.resources.system_args[id]);
  auto &args = std::get<1>(bpftrace.resources.system_args[id]);
  auto vals = prepare_args(
      bpftrace, c_definitions, args, data.slice(sizeof(uint64_t)));
  if (!vals) {
    return vals.takeError();
  }

  // Always execute via a shell, if available.
  std::vector<std::string> system_args;
  system_args.emplace_back("sh");
  system_args.emplace_back("-c");
  system_args.emplace_back(fmt.format(*vals));
  auto result = util::exec_system(system_args);
  if (!result) {
    return result.takeError();
  }

  out->syscall(*result);
  return OK();
}

Result<> AsyncHandlers::cat(const OpaqueValue &data)
{
  auto id = data.bitcast<uint64_t>() - static_cast<uint64_t>(AsyncAction::cat);
  auto &fmt = std::get<0>(bpftrace.resources.cat_args[id]);
  auto &args = std::get<1>(bpftrace.resources.cat_args[id]);
  auto vals = prepare_args(
      bpftrace, c_definitions, args, data.slice(sizeof(uint64_t)));
  if (!vals) {
    return vals.takeError();
  }

  auto filename = fmt.format(*vals);
  auto file = std::ifstream(filename, std::ios::binary);
  if (file.fail()) {
    return make_error<SystemError>("Failed to open file '" + filename + "'");
  }

  // Read up to the maximum bytes specified.
  std::string str;
  str.resize(bpftrace.config_->max_cat_bytes);
  file.read(&str[0], bpftrace.config_->max_cat_bytes);
  str.resize(file.gcount());
  out->cat(str);
  return OK();
}

Result<> AsyncHandlers::printf(const OpaqueValue &data)
{
  auto id = data.bitcast<uint64_t>() -
            static_cast<uint64_t>(AsyncAction::printf);
  auto &fmt = std::get<0>(bpftrace.resources.printf_args[id]);
  auto &args = std::get<1>(bpftrace.resources.printf_args[id]);
  auto severity = std::get<2>(bpftrace.resources.printf_args[id]);
  auto &source_info = std::get<3>(bpftrace.resources.printf_args[id]);
  auto vals = prepare_args(
      bpftrace, c_definitions, args, data.slice(sizeof(uint64_t)));
  if (!vals) {
    return vals.takeError();
  }

  if (severity == PrintfSeverity::WARNING && bpftrace.warning_level_ == 0) {
    return OK();
  }

  out->printf(fmt.format(*vals), source_info, severity);
  return OK();
}

} // namespace bpftrace::async_action
