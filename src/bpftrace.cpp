#include <arpa/inet.h>
#include <bcc/bcc_elf.h>
#include <bcc/bcc_syms.h>
#include <bcc/perf_reader.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <glob.h>
#include <iostream>
#include <ranges>
#include <regex>
#include <sstream>
#include <sys/epoll.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef HAVE_LIBSYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "ast/async_event_types.h"
#include "ast/context.h"
#include "async_action.h"
#include "attached_probe.h"
#include "bpfmap.h"
#include "bpfprogram.h"
#include "bpftrace.h"
#include "btf.h"
#include "log.h"
#include "printf.h"
#include "scopeguard.h"
#include "util/bpf_names.h"
#include "util/cgroup.h"
#include "util/cpus.h"
#include "util/exceptions.h"
#include "util/kernel.h"
#include "util/paths.h"
#include "util/strings.h"
#include "util/system.h"
#include "util/wildcard.h"

using namespace std::chrono_literals;

namespace bpftrace {

std::set<DebugStage> bt_debug = {};
bool bt_quiet = false;
bool bt_verbose = false;
bool dry_run = false;
int BPFtrace::exit_code = 0;
volatile sig_atomic_t BPFtrace::exitsig_recv = false;
volatile sig_atomic_t BPFtrace::sigusr1_recv = false;

static void log_probe_attach_failure(const std::string &err_msg,
                                     const std::string &name,
                                     ConfigMissingProbes missing_probes)
{
  if (missing_probes == ConfigMissingProbes::error) {
    if (!err_msg.empty()) {
      LOG(ERROR) << err_msg;
    }
    LOG(ERROR) << "Unable to attach probe: " << name
               << ". If this is expected, set the 'missing_probes' "
                  "config variable to 'warn'.";
  } else if (missing_probes == ConfigMissingProbes::warn) {
    if (!err_msg.empty()) {
      LOG(WARNING) << err_msg;
    }
    LOG(WARNING) << "Unable to attach probe: " << name << ". Skipping.";
  }
}

BPFtrace::~BPFtrace()
{
  close_pcaps();
}

Probe BPFtrace::generateWatchpointSetupProbe(const ast::AttachPoint &ap,
                                             const ast::Probe &probe)
{
  Probe setup_probe;
  setup_probe.name = util::get_watchpoint_setup_probe_name(ap.name());
  setup_probe.type = ProbeType::uprobe;
  setup_probe.path = ap.target;
  setup_probe.attach_point = ap.func;
  setup_probe.orig_name = util::get_watchpoint_setup_probe_name(
      probe.orig_name);
  setup_probe.index = ap.index() > 0 ? ap.index() : probe.index();

  return setup_probe;
}

Probe BPFtrace::generate_probe(const ast::AttachPoint &ap,
                               const ast::Probe &p,
                               ast::ExpansionType expansion,
                               std::set<std::string> expanded_funcs,
                               int usdt_location_idx)
{
  Probe probe;
  probe.path = ap.target;
  probe.attach_point = ap.func;
  probe.type = probetype(ap.provider);
  probe.log_size = config_->log_size;
  probe.orig_name = p.orig_name;
  probe.ns = ap.ns;
  probe.name = ap.name();
  probe.freq = ap.freq;
  probe.address = ap.address;
  probe.func_offset = ap.func_offset;
  probe.loc = 0;
  probe.usdt_location_idx = usdt_location_idx;
  probe.index = ap.index() ?: p.index();
  probe.len = ap.len;
  probe.mode = ap.mode;
  probe.async = ap.async;
  probe.pin = ap.pin;
  probe.is_session = expansion == ast::ExpansionType::SESSION;
  probe.funcs = std::move(expanded_funcs);
  probe.bpf_prog_id = ap.bpf_prog_id;
  return probe;
}

int BPFtrace::add_probe(const ast::AttachPoint &ap,
                        const ast::Probe &p,
                        ast::ExpansionType expansion,
                        std::set<std::string> expanded_funcs,
                        int usdt_location_idx)
{
  auto type = probetype(ap.provider);
  auto probe = generate_probe(
      ap, p, expansion, std::move(expanded_funcs), usdt_location_idx);

  // Add the new probe(s) to resources
  if (ap.provider == "begin" || ap.provider == "end") {
    // special probes
    auto target = ap.target.empty() ? "" : "_" + ap.target;
    auto name = ap.provider + target;
    resources.special_probes[name] = std::move(probe);
  } else if (ap.provider == "bench") {
    resources.benchmark_probes.emplace_back(std::move(probe));
  } else if (ap.provider == "self") {
    if (ap.target == "signal") {
      resources.signal_probes.emplace_back(std::move(probe));
    }
  } else if ((type == ProbeType::watchpoint ||
              type == ProbeType::asyncwatchpoint) &&
             !ap.func.empty()) {
    // (async)watchpoint - generate also the setup probe
    resources.probes.emplace_back(generateWatchpointSetupProbe(ap, p));
    resources.watchpoint_probes.emplace_back(std::move(probe));
  } else {
    resources.probes.emplace_back(std::move(probe));
  }

  if (type == ProbeType::iter)
    has_iter_ = true;

  // Preload symbol tables if necessary
  if (resources.probes_using_usym.contains(&p) && util::is_exe(ap.target)) {
    usyms_.cache(ap.target, this->pid());
  }

  return 0;
}

int BPFtrace::num_probes() const
{
  return resources.special_probes.size() + resources.probes.size() +
         resources.signal_probes.size() + resources.benchmark_probes.size();
}

void BPFtrace::request_finalize()
{
  finalize_ = true;
  attached_probes_.clear();
  if (child_)
    child_->terminate();
}

// PerfEventContext is our callback wrapper.
struct PerfEventContext {
  PerfEventContext(BPFtrace &b,
                   async_action::AsyncHandlers &handlers,
                   output::Output &o)
      : bpftrace(b), handlers(handlers), output(o) {};
  BPFtrace &bpftrace;
  async_action::AsyncHandlers &handlers;
  output::Output &output;
};

void perf_event_printer(void *cb_cookie, void *raw_data, int size)
{
  auto *ctx = static_cast<PerfEventContext *>(cb_cookie);

  // N.B. This will copy the value into its own buffer, potentially allocating
  // and freeing a new chunk if it is larger than a single word. This is
  // guaranteed to be aligned.
  auto data = OpaqueValue::alloc(size, [&](char *data) {
    memcpy(data, raw_data, size);
  });

  // Ignore the remaining events if perf_event_printer is called during
  // finalization stage (exit() builtin has been called)
  if (ctx->bpftrace.finalize_)
    return;

  if (bpftrace::BPFtrace::exitsig_recv) {
    ctx->bpftrace.request_finalize();
    return;
  }

  // async actions
  auto printf_id = async_action::AsyncAction(data.bitcast<uint64_t>());
  if (printf_id == async_action::AsyncAction::exit) {
    ctx->handlers.exit(data);
    return;
  } else if (printf_id == async_action::AsyncAction::print) {
    ctx->handlers.print_map(data);
    return;
  } else if (printf_id == async_action::AsyncAction::print_non_map) {
    ctx->handlers.print_non_map(data);
    return;
  } else if (printf_id == async_action::AsyncAction::clear) {
    ctx->handlers.clear_map(data);
    return;
  } else if (printf_id == async_action::AsyncAction::zero) {
    ctx->handlers.zero_map(data);
    return;
  } else if (printf_id == async_action::AsyncAction::time) {
    ctx->handlers.time(data);
    return;
  } else if (printf_id == async_action::AsyncAction::join) {
    ctx->handlers.join(data);
    return;
  } else if (printf_id == async_action::AsyncAction::runtime_error) {
    ctx->handlers.runtime_error(data);
    return;
  } else if (printf_id == async_action::AsyncAction::watchpoint_attach) {
    ctx->handlers.watchpoint_attach(data);
    return;
  } else if (printf_id == async_action::AsyncAction::watchpoint_detach) {
    ctx->handlers.watchpoint_detach(data);
    return;
  } else if (printf_id == async_action::AsyncAction::skboutput) {
    ctx->handlers.skboutput(data);
    return;
  } else if (printf_id >= async_action::AsyncAction::syscall &&
             printf_id <= async_action::AsyncAction::syscall_end) {
    ctx->handlers.syscall(data);
    return;
  } else if (printf_id >= async_action::AsyncAction::cat &&
             printf_id <= async_action::AsyncAction::cat_end) {
    ctx->handlers.cat(data);
    return;
  } else if (printf_id >= async_action::AsyncAction::printf &&
             printf_id <= async_action::AsyncAction::printf_end) {
    ctx->handlers.printf(data);
    return;
  } else if (printf_id >= async_action::AsyncAction::print_error &&
             printf_id <= async_action::AsyncAction::print_error_end) {
    ctx->handlers.print_error(data);
    return;
  } else {
    LOG(BUG) << "Unknown printf_id: " << static_cast<int64_t>(printf_id);
  }
}

int ringbuf_printer(void *cb_cookie, void *data, size_t size)
{
  perf_event_printer(cb_cookie, data, size);
  return 0;
}

std::vector<std::unique_ptr<IPrintable>> BPFtrace::get_arg_values(
    const ast::CDefinitions &c_definitions,
    const std::vector<Field> &args,
    const char *arg_data)
{
  std::vector<std::unique_ptr<IPrintable>> arg_values;

  for (auto arg : args) {
    switch (arg.type.GetTy()) {
      case Type::boolean:
        arg_values.push_back(std::make_unique<PrintableInt>(
            *reinterpret_cast<const uint8_t *>(arg_data + arg.offset)));
        break;
      case Type::integer:
        if (arg.type.IsSigned()) {
          int64_t val = 0;
          switch (arg.type.GetIntBitWidth()) {
            case 64:
              val = *reinterpret_cast<const int64_t *>(arg_data + arg.offset);
              break;
            case 32:
              val = *reinterpret_cast<const int32_t *>(arg_data + arg.offset);
              break;
            case 16:
              val = *reinterpret_cast<const int16_t *>(arg_data + arg.offset);
              break;
            case 8:
              val = *reinterpret_cast<const int8_t *>(arg_data + arg.offset);
              break;
            case 1:
              val = *reinterpret_cast<const int8_t *>(arg_data + arg.offset);
              break;
            default:
              throw util::FatalUserException(
                  "get_arg_values: invalid integer size. "
                  "8, 4, 2 and byte supported. " +
                  std::to_string(arg.type.GetSize()) + "provided");
          }
          arg_values.push_back(std::make_unique<PrintableSInt>(val));
        } else {
          uint64_t val = 0;
          switch (arg.type.GetIntBitWidth()) {
            case 64:
              val = *reinterpret_cast<const uint64_t *>(arg_data + arg.offset);
              break;
            case 32:
              val = *reinterpret_cast<const uint32_t *>(arg_data + arg.offset);
              break;
            case 16:
              val = *reinterpret_cast<const uint16_t *>(arg_data + arg.offset);
              break;
            case 8:
              val = *reinterpret_cast<const uint8_t *>(arg_data + arg.offset);
              break;
            case 1:
              val = *reinterpret_cast<const uint8_t *>(arg_data + arg.offset);
              break;
            default:
              throw util::FatalUserException(
                  "get_arg_values: invalid integer size. "
                  "8, 4, 2 and byte supported. " +
                  std::to_string(arg.type.GetSize()) + "provided");
          }

          if (arg.type.IsEnumTy()) {
            auto enum_name = arg.type.GetName();
            if (c_definitions.enum_defs.contains(enum_name) &&
                c_definitions.enum_defs.find(enum_name)->second.contains(val)) {
              arg_values.push_back(std::make_unique<PrintableEnum>(
                  val,
                  c_definitions.enum_defs.find(enum_name)
                      ->second.find(val)
                      ->second));
            } else {
              arg_values.push_back(
                  std::make_unique<PrintableEnum>(val, std::to_string(val)));
            }
          } else {
            arg_values.push_back(std::make_unique<PrintableInt>(val));
          }
        }
        break;
      case Type::string: {
        const auto *p = reinterpret_cast<const char *>(arg_data + arg.offset);
        arg_values.push_back(std::make_unique<PrintableString>(
            std::string(p, strnlen(p, arg.type.GetSize())),
            config_->max_strlen,
            config_->str_trunc_trailer.c_str()));
        break;
      }
      case Type::buffer: {
        auto length = reinterpret_cast<const AsyncEvent::Buf *>(arg_data +
                                                                arg.offset)
                          ->length;
        arg_values.push_back(std::make_unique<PrintableBuffer>(
            reinterpret_cast<const AsyncEvent::Buf *>(arg_data + arg.offset)
                ->content,
            length));
        break;
      }
      case Type::ksym_t:
        arg_values.push_back(std::make_unique<PrintableString>(resolve_ksym(
            *reinterpret_cast<const uint64_t *>(arg_data + arg.offset))));
        break;
      case Type::usym_t:
        arg_values.push_back(std::make_unique<PrintableString>(resolve_usym(
            *reinterpret_cast<const uint64_t *>(arg_data + arg.offset),
            *reinterpret_cast<const int32_t *>(arg_data + arg.offset + 8),
            *reinterpret_cast<const int32_t *>(arg_data + arg.offset + 12))));
        break;
      case Type::inet:
        arg_values.push_back(std::make_unique<PrintableString>(resolve_inet(
            *reinterpret_cast<const int64_t *>(arg_data + arg.offset),
            reinterpret_cast<const char *>(arg_data + arg.offset + 8))));
        break;
      case Type::username:
        arg_values.push_back(std::make_unique<PrintableString>(resolve_uid(
            *reinterpret_cast<const uint64_t *>(arg_data + arg.offset))));
        break;
      case Type::kstack_t:
        arg_values.push_back(std::make_unique<PrintableString>(get_stack(
            *reinterpret_cast<const int64_t *>(arg_data + arg.offset),
            *reinterpret_cast<const uint32_t *>(arg_data + arg.offset + 8),
            -1,
            -1,
            false,
            arg.type.stack_type,
            8)));
        break;
      case Type::ustack_t:
        arg_values.push_back(std::make_unique<PrintableString>(get_stack(
            *reinterpret_cast<const int64_t *>(arg_data + arg.offset),
            *reinterpret_cast<const uint32_t *>(arg_data + arg.offset + 8),
            *reinterpret_cast<const int32_t *>(arg_data + arg.offset + 16),
            *reinterpret_cast<const int32_t *>(arg_data + arg.offset + 20),
            true,
            arg.type.stack_type,
            8)));
        break;
      case Type::timestamp: {
        const auto *strftime = reinterpret_cast<const AsyncEvent::Strftime *>(
            arg_data + arg.offset);
        auto ts = resolve_timestamp(strftime->mode, strftime->nsecs);
        auto s = format_timestamp(ts, strftime->strftime_id);
        arg_values.push_back(std::make_unique<PrintableString>(std::move(s)));
        break;
      }
      case Type::pointer:
        arg_values.push_back(std::make_unique<PrintableInt>(
            *reinterpret_cast<const uint64_t *>(arg_data + arg.offset)));
        break;
      case Type::mac_address:
        arg_values.push_back(
            std::make_unique<PrintableString>(resolve_mac_address(
                reinterpret_cast<const char *>(arg_data + arg.offset))));
        break;
      case Type::cgroup_path_t:
        arg_values.push_back(
            std::make_unique<PrintableString>(resolve_cgroup_path(
                reinterpret_cast<const AsyncEvent::CgroupPath *>(arg_data +
                                                                 arg.offset)
                    ->cgroup_path_id,
                reinterpret_cast<const AsyncEvent::CgroupPath *>(arg_data +
                                                                 arg.offset)
                    ->cgroup_id)));
        break;
      case Type::strerror_t:
        arg_values.push_back(std::make_unique<PrintableString>(strerror(
            *reinterpret_cast<const uint64_t *>(arg_data + arg.offset))));
        break;
        // fall through
      default:
        LOG(BUG) << "invalid argument type";
    }
  }

  return arg_values;
}

void BPFtrace::add_param(const std::string &param)
{
  params_.emplace_back(param);
}

std::string BPFtrace::get_param(size_t i) const
{
  if (params_.size() < i) {
    return "";
  }
  return params_.at(i - 1);
}

size_t BPFtrace::num_params() const
{
  return params_.size();
}

void perf_event_lost(void *cb_cookie, uint64_t lost)
{
  auto *ctx = static_cast<PerfEventContext *>(cb_cookie);
  ctx->output.lost_events(lost);
}

Result<std::unique_ptr<AttachedProbe>> BPFtrace::attach_probe(
    Probe &probe,
    const BpfBytecode &bytecode)
{
  const auto &program = bytecode.getProgramForProbe(probe);
  std::optional<pid_t> pid = child_ ? std::make_optional(child_->pid())
                                    : this->pid();

  auto ap = AttachedProbe::make(probe, program, pid, *this, safe_mode_);
  if (!ap) {
    auto missing_probes = config_->missing_probes;
    auto ok = handleErrors(std::move(ap), [&](const AttachError &err) {
      log_probe_attach_failure(err.msg(), probe.name, missing_probes);
    });
    return make_error<AttachError>();
  } else {
    return std::move(*ap);
  }
}

bool attach_reverse(const Probe &p)
{
  switch (p.type) {
    case ProbeType::special:
    case ProbeType::benchmark:
    case ProbeType::kprobe:
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::usdt:
    case ProbeType::fentry:
    case ProbeType::fexit:
    case ProbeType::iter:
      return true;
    case ProbeType::kretprobe:
    case ProbeType::tracepoint:
    case ProbeType::profile:
    case ProbeType::interval:
    case ProbeType::watchpoint:
    case ProbeType::asyncwatchpoint:
    case ProbeType::hardware:
    case ProbeType::rawtracepoint:
    case ProbeType::software:
      return false;
    case ProbeType::invalid:
      LOG(BUG) << "Unknown probe type";
  }

  return {}; // unreached
}

int BPFtrace::run_iter()
{
  auto probe = resources.probes.begin();
  char buf[1024] = {};
  ssize_t len;

  if (probe == resources.probes.end()) {
    LOG(ERROR) << "Failed to create iter probe";
    return 1;
  }

  // If a script contains an iter probe, it must be the only probe
  assert(attached_probes_.size() == 1);
  if (attached_probes_.empty()) {
    LOG(ERROR) << "Failed to attach iter probe";
    return 1;
  }

  auto &ap = *attached_probes_.begin();
  int link_fd = ap->link_fd();

  if (probe->pin.empty()) {
    int iter_fd = bpf_iter_create(link_fd);

    if (iter_fd < 0) {
      LOG(ERROR) << "Failed to open iter probe link";
      return 1;
    }

    while ((len = read(iter_fd, buf, sizeof(buf))) > 0) {
      fwrite(buf, len, 1, stdout);
    }

    close(iter_fd);
  } else {
    auto pin = probe->pin;

    if (pin.at(0) != '/')
      pin = "/sys/fs/bpf/" + pin;

    if (bpf_obj_pin(link_fd, pin.c_str()))
      LOG(ERROR) << "Failed to pin iter probe link";
    else
      std::cout << "Program pinned to " << pin << std::endl;
  }

  return 0;
}

int BPFtrace::prerun() const
{
  uint64_t num_probes = this->num_probes();
  const auto max_probes = config_->max_probes;
  if (num_probes == 0) {
    if (!bt_quiet)
      std::cout << "No probes to attach" << std::endl;
    return 1;
  } else if (num_probes > max_probes) {
    LOG(ERROR)
        << "Can't attach to " << num_probes << " probes because it "
        << "exceeds the current limit of " << max_probes << " probes.\n"
        << "You can increase the limit through the BPFTRACE_MAX_PROBES "
        << "environment variable, but BE CAREFUL since a high number of probes "
        << "attached can cause your system to crash.";
    return 1;
  }

  return 0;
}

int BPFtrace::run(output::Output &out,
                  const ast::CDefinitions &c_definitions,
                  BpfBytecode bytecode)
{
  int err = prerun();
  if (err)
    return err;

  bytecode_ = std::move(bytecode);
  bytecode_.set_map_ids(resources);

  try {
    bytecode_.load_progs(resources, *btf_, *feature_, *config_);
  } catch (const HelperVerifierError &e) {
    // To provide the most useful diagnostics, provide the error for every
    // callsite. After all, they all must be fixed.
    bool found = false;
    for (const auto &info : helper_use_loc_[e.func_id]) {
      bool first = true;
      for (const auto &loc : info.locations) {
        if (first) {
          LOG(ERROR,
              std::string(loc.source_location),
              std::vector(loc.source_context))
              << e.what();
          first = false;
        } else {
          LOG(ERROR,
              std::string(loc.source_location),
              std::vector(loc.source_context))
              << "expanded from";
        }
      }

      found = true;
    }
    if (!found) {
      // An error occurred, but we don't have location for this helper. It may
      // be a C file or elsewhere, and we need to plumb this through somehow.
      // At least inform the user what has gone wrong in this case.
      LOG(ERROR) << e.what();
    }
    return -1;
  } catch (const std::runtime_error &e) {
    LOG(ERROR) << e.what();
    return -1;
  }

  async_action::AsyncHandlers handlers(*this, c_definitions, out);
  PerfEventContext ctx(*this, handlers, out);
  err = setup_output(&ctx);
  if (err)
    return err;
  SCOPE_EXIT
  {
    teardown_output();
  };

  err = create_pcaps();
  if (err) {
    LOG(ERROR) << "Failed to create pcap file(s)";
    return err;
  }

  if (bytecode_.hasMap(MapType::Elapsed)) {
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    auto nsec = (1000000000ULL * ts.tv_sec) + ts.tv_nsec;
    uint64_t key = 0;
    auto map = bytecode_.getMap(MapType::Elapsed);
    auto ok = map.update_elem(&key, &nsec);
    if (!ok) {
      LOG(ERROR) << "Failed to write start time to elapsed map: "
                 << ok.takeError();
      return -1;
    }
  }

  int num_begin_end_attached = 0;
  int num_signal_attached = 0;

  auto begin_probe = resources.special_probes.find("begin");
  if (begin_probe != resources.special_probes.end()) {
    auto &begin_prog = bytecode_.getProgramForProbe((*begin_probe).second);
    if (::bpf_prog_test_run_opts(begin_prog.fd(), nullptr))
      return -1;

    LOG(V1) << "Attaching 'begin' probe";
    ++num_begin_end_attached;
  }

  if (resources.special_probes.contains("end")) {
    ++num_begin_end_attached;
  }

  if (run_benchmarks_) {
    for (auto &probe : resources.benchmark_probes) {
      auto &benchmark_prog = bytecode_.getProgramForProbe(probe);
      // Note: on newer kernels you must provide a data_in buffer at least
      // ETH_HLEN bytes long to make sure input validation works for
      // opts. Otherwise, bpf_prog_test_run_opts will return -EINVAL for
      // BPF_PROG_TYPE_XDP.
      //
      // https://github.com/torvalds/linux/commit/6b3d638ca897e099fa99bd6d02189d3176f80a47
      constexpr size_t ETH_HLEN = 14;
      char data_in[ETH_HLEN];
      struct ::bpf_test_run_opts opts = {};
      opts.sz = sizeof(struct ::bpf_test_run_opts);
      opts.data_in = data_in;
      opts.data_size_in = ETH_HLEN;
      opts.repeat = 1'000'000;

      if (auto ret = ::bpf_prog_test_run_opts(benchmark_prog.fd(), &opts)) {
        LOG(ERROR) << "bpf_prog_test_run_opts failed: " << ret;
        return -1;
      }

      benchmark_results.emplace_back(probe.path, opts.duration);
    }
  } else {
    for (auto &probe : resources.signal_probes) {
      auto &sig_prog = bytecode_.getProgramForProbe(probe);
      sigusr1_prog_fds_.emplace_back(sig_prog.fd());
      ++num_signal_attached;
    }

    if (child_ && has_usdt_) {
      try {
        child_->run(true);
      } catch (const std::exception &e) {
        LOG(ERROR) << "Failed to setup child: " << e.what();
        return -1;
      }
    }

    bytecode_.attach_external();

    // The kernel appears to fire some probes in the order that they were
    // attached and others in reverse order. In order to make sure that blocks
    // are executed in the same order they were declared, iterate over the
    // probes twice: in the first pass iterate forward and attach the probes
    // that will be fired in the same order they were attached, and in the
    // second pass iterate in reverse and attach the rest.
    for (auto &probe : resources.probes) {
      if (BPFtrace::exitsig_recv) {
        request_finalize();
        return -1;
      }
      if (!attach_reverse(probe)) {
        auto ap = attach_probe(probe, bytecode_);
        if (!ap) {
          if (config_->missing_probes == ConfigMissingProbes::error) {
            return -1;
          }
        } else {
          attached_probes_.push_back(std::move(*ap));
        }
      }
    }

    for (auto &probe : std::ranges::reverse_view(resources.probes)) {
      if (BPFtrace::exitsig_recv) {
        request_finalize();
        return -1;
      }
      if (attach_reverse(probe)) {
        auto ap = attach_probe(probe, bytecode_);
        if (!ap) {
          if (config_->missing_probes == ConfigMissingProbes::error) {
            return -1;
          }
        } else {
          attached_probes_.push_back(std::move(*ap));
        }
      }
    }

    if (dry_run) {
      request_finalize();
      return 0;
    }

    // Kick the child to execute the command.
    if (child_) {
      try {
        if (has_usdt_)
          child_->resume();
        else
          child_->run();
      } catch (const std::exception &e) {
        LOG(ERROR) << "Failed to run child: " << e.what();
        return -1;
      }
    }
  }

  size_t num_attached = 0;

  for (auto &ap : attached_probes_) {
    num_attached += ap->probe_count();
  }

  auto total_attached = num_attached + num_begin_end_attached +
                        num_signal_attached + benchmark_results.size();

  if (total_attached == 0) {
    LOG(ERROR) << "Attachment failed for all probes.";
    return -1;
  }

  if (!bt_quiet)
    out.attached_probes(total_attached);

  // Used by runtime test framework to know when to run AFTER directive
  if (std::getenv("__BPFTRACE_NOTIFY_PROBES_ATTACHED"))
    std::cout << "__BPFTRACE_NOTIFY_PROBES_ATTACHED" << std::endl;

#ifdef HAVE_LIBSYSTEMD
  err = sd_notify(false, "READY=1\nSTATUS=Processing events...");
  if (err < 0)
    LOG(WARNING) << "Failed to send readiness notification, ignoring: "
                 << strerror(-err);
#endif

  if (has_iter_) {
    int err = run_iter();
    if (err)
      return err;
  } else {
    bool should_drain = (num_begin_end_attached > 0 || run_benchmarks_) &&
                        num_signal_attached == 0 && num_attached == 0;
    poll_output(out, should_drain);
  }

#ifdef HAVE_LIBSYSTEMD
  err = sd_notify(false, "STOPPING=1\nSTATUS=Shutting down...");
  if (err < 0)
    LOG(WARNING) << "Failed to send shutdown notification, ignoring: "
                 << strerror(-err);
#endif

  attached_probes_.clear();
  // finalize_ and exitsig_recv should be false from now on otherwise
  // perf_event_printer() can ignore the `end` events.
  finalize_ = false;
  exitsig_recv = false;

  auto end_probe = resources.special_probes.find("end");
  if (end_probe != resources.special_probes.end()) {
    auto &end_prog = bytecode_.getProgramForProbe((*end_probe).second);
    if (::bpf_prog_test_run_opts(end_prog.fd(), nullptr))
      return -1;

    LOG(V1) << "Attaching 'end' probe";
  }

  poll_output(out, /* drain */ true);

  uint64_t total_lost_events = bytecode_.get_event_loss_counter(*this,
                                                                max_cpu_id_);
  if (total_lost_events > 0) {
    // We incrementally log lost event counts to stdout via `output`
    // so users can get a record of it in their txt/json output
    // but let's log to stderr here to make sure this message doesn't
    // get lost to users in scripts with high frequency output
    LOG(WARNING) << "Total lost event count: " << total_lost_events;
  }

  return 0;
}

int BPFtrace::setup_output(void *ctx)
{
  setup_ringbuf(ctx);
  if (resources.using_skboutput) {
    return setup_skboutput_perf_buffer(ctx);
  }
  return 0;
}

int BPFtrace::setup_skboutput_perf_buffer(void *ctx)
{
  epollfd_ = epoll_create1(EPOLL_CLOEXEC);
  if (epollfd_ == -1) {
    LOG(ERROR) << "Failed to create epollfd";
    return -1;
  }

  std::vector<int> cpus = util::get_online_cpus();
  online_cpus_ = cpus.size();
  for (int cpu : cpus) {
    void *reader = bpf_open_perf_buffer(&perf_event_printer,
                                        &perf_event_lost,
                                        ctx,
                                        -1,
                                        cpu,
                                        config_->perf_rb_pages);
    if (reader == nullptr) {
      LOG(ERROR) << "Failed to open perf buffer";
      return -1;
    }
    // Store the perf buffer pointers in a vector of unique_ptrs.
    // When open_perf_buffers_ is cleared or destroyed,
    // perf_reader_free is automatically called.
    open_perf_buffers_.emplace_back(reader, perf_reader_free);

    struct epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.ptr = reader;
    int reader_fd = perf_reader_fd(static_cast<perf_reader *>(reader));

    auto map = bytecode_.getMap(MapType::PerfEvent);
    auto ok = map.update_elem(&cpu, &reader_fd);
    if (!ok) {
      LOG(ERROR) << "Failed to update perf event map: " << ok.takeError();
      return -1;
    }
    if (epoll_ctl(epollfd_, EPOLL_CTL_ADD, reader_fd, &ev) == -1) {
      LOG(ERROR) << "Failed to add perf reader to epoll";
      return -1;
    }
  }
  return 0;
}

void BPFtrace::setup_ringbuf(void *ctx)
{
  ringbuf_ = ring_buffer__new(
      bytecode_.getMap(MapType::Ringbuf).fd(), ringbuf_printer, ctx, nullptr);
}

void BPFtrace::teardown_output()
{
  ring_buffer__free(ringbuf_);

  if (resources.using_skboutput)
    // Calls perf_reader_free() on all open perf buffers.
    open_perf_buffers_.clear();
}

void BPFtrace::poll_output(output::Output &out, bool drain)
{
  int ready;
  bool poll_skboutput = resources.using_skboutput;
  bool do_poll_ringbuf = true;
  auto should_retry = [](int ready) {
    // epoll_wait will set errno to EINTR if an interrupt received, it is
    // retryable if not caused by SIGINT. ring_buffer__poll does not set errno,
    // we will keep retrying till SIGINT.
    return ready < 0 && (errno == 0 || errno == EINTR) &&
           !BPFtrace::exitsig_recv;
  };
  auto should_stop = [this, drain](int ready) {
    // Stop if either
    //   * an exit signal is received
    //   * epoll_wait has encountered an error (eg signal delivery)
    //   * there's no events left and we've been instructed to drain or
    //     finalization has been requested through exit() builtin.
    return BPFtrace::exitsig_recv || ready < 0 ||
           (ready == 0 && (drain || finalize_));
  };

  if (poll_skboutput && epollfd_ < 0) {
    LOG(ERROR) << "Invalid epollfd " << epollfd_;
    return;
  }

  while (true) {
    if (poll_skboutput) {
      ready = poll_skboutput_events();
      if (should_retry(ready)) {
        if (!do_poll_ringbuf)
          continue;
      }
      if (should_stop(ready)) {
        poll_skboutput = false;
      }
    }

    // Handle lost events, if any
    poll_event_loss(out);

    if (do_poll_ringbuf) {
      ready = ring_buffer__poll(ringbuf_, timeout_ms);
      if (should_retry(ready)) {
        continue;
      }
      if (should_stop(ready)) {
        do_poll_ringbuf = false;
      }
    }
    if (!poll_skboutput && !do_poll_ringbuf) {
      return;
    }

    // If we are tracing a specific pid and it has exited, we should exit
    // as well b/c otherwise we'd be tracing nothing.
    if ((procmon_ && !procmon_->is_alive()) ||
        (child_ && !child_->is_alive())) {
      return;
    }

    if (BPFtrace::sigusr1_recv) {
      BPFtrace::sigusr1_recv = false;

      for (auto fd : sigusr1_prog_fds_) {
        if (::bpf_prog_test_run_opts(fd, nullptr)) {
          LOG(ERROR) << "Failed to run signal probe";
          return;
        }
        LOG(V1) << "Attaching 'self:signal' probe";
      }
    }
  }
}

int BPFtrace::poll_skboutput_events()
{
  auto events = std::vector<struct epoll_event>(online_cpus_);
  int ready = epoll_wait(epollfd_, events.data(), online_cpus_, timeout_ms);
  if (ready <= 0) {
    return ready;
  }
  for (int i = 0; i < ready; i++) {
    perf_reader_event_read(static_cast<perf_reader *>(events[i].data.ptr));
  }
  return ready;
}

void BPFtrace::poll_event_loss(output::Output &out)
{
  uint64_t current_value = bytecode_.get_event_loss_counter(*this, max_cpu_id_);

  if (current_value > event_loss_count_) {
    out.lost_events(current_value - event_loss_count_);
    event_loss_count_ = current_value;
  } else if (current_value < event_loss_count_) {
    LOG(ERROR) << "Invalid event loss count value: " << current_value
               << ", last seen: " << event_loss_count_;
  }
}

std::optional<std::string> BPFtrace::get_watchpoint_binary_path() const
{
  if (child_) {
    // We can ignore all error checking here b/c child.cpp:validate_cmd() has
    // already done it
    auto args = util::split_string(cmd_, ' ', /* remove_empty */ true);
    assert(!args.empty());
    return util::resolve_binary_path(args[0]).front();
  } else if (pid().has_value())
    return "/proc/" + std::to_string(pid().value_or(0)) + "/exe";
  else {
    return std::nullopt;
  }
}

std::string BPFtrace::get_stack(int64_t stackid,
                                uint32_t nr_stack_frames,
                                int32_t pid,
                                int32_t probe_id,
                                bool ustack,
                                StackType stack_type,
                                int indent)
{
  struct stack_key stack_key = { .stackid = stackid,
                                 .nr_stack_frames = nr_stack_frames };
  auto stack_trace = std::vector<uint64_t>(stack_type.limit);
  auto map = bytecode_.getMap(stack_type.name());
  auto ok = map.lookup_elem(&stack_key, stack_trace.data());
  if (!ok) {
    LOG(ERROR) << "failed to look up stack id: " << stackid
               << " stack length: " << nr_stack_frames << " (pid " << pid
               << "): " << ok.takeError();
    return "";
  }

  std::ostringstream stack;
  std::string padding(indent, ' ');

  stack << "\n";
  for (uint32_t i = 0; i < nr_stack_frames;) {
    uint64_t addr = stack_trace.at(i);
    if (stack_type.mode == StackMode::raw) {
      stack << std::hex << addr << std::endl;
      ++i;
      continue;
    }
    std::vector<std::string> syms;
    if (!ustack)
      syms = resolve_ksym_stack(addr,
                                true,
                                stack_type.mode == StackMode::perf,
                                config_->show_debug_info);
    else
      syms = resolve_usym_stack(addr,
                                pid,
                                probe_id,
                                true,
                                stack_type.mode == StackMode::perf,
                                config_->show_debug_info);

    std::string sym;
    for (size_t sym_idx = 0; i < nr_stack_frames && sym_idx < syms.size();) {
      sym = syms.at(sym_idx);
      switch (stack_type.mode) {
        case StackMode::bpftrace:
          stack << padding << sym << std::endl;
          break;
        case StackMode::perf:
          stack << "\t" << std::hex << addr << std::dec << " " << sym
                << std::endl;
          break;
        case StackMode::raw:
          LOG(BUG) << "StackMode::raw should have been processed before "
                      "symbolication.";
          break;
      }
      ++i;
      ++sym_idx;
    }
  }

  return stack.str();
}

std::string BPFtrace::resolve_uid(uint64_t addr) const
{
  std::string file_name = "/etc/passwd";
  std::string uid = std::to_string(addr);
  std::string username;

  std::ifstream file(file_name);
  if (file.fail()) {
    LOG(ERROR) << strerror(errno) << ": " << file_name;
    return username;
  }

  std::string line;
  bool found = false;

  while (std::getline(file, line) && !found) {
    auto fields = util::split_string(line, ':');

    if (fields.size() >= 3 && fields[2] == uid) {
      found = true;
      username = fields[0];
    }
  }

  file.close();

  return username;
}

std::chrono::time_point<std::chrono::system_clock> BPFtrace::resolve_timestamp(
    uint32_t mode,
    uint64_t nsecs)
{
  std::chrono::time_point<std::chrono::system_clock> t;
  auto ts_mode = static_cast<TimestampMode>(mode);
  if (ts_mode == TimestampMode::boot) {
    if (!boottime_) {
      LOG(ERROR)
          << "Cannot resolve timestamp due to failed boot time calculation";
    } else {
      t += std::chrono::seconds(boottime_->tv_sec);
      t += std::chrono::nanoseconds(boottime_->tv_nsec);
    }
  }

  t += std::chrono::nanoseconds(nsecs);
  return t;
}

std::string BPFtrace::format_timestamp(
    const std::chrono::time_point<std::chrono::system_clock> &time_point,
    uint32_t strftime_id)
{
  return format_timestamp(time_point,
                          resources.strftime_args[strftime_id],
                          false);
}

std::string BPFtrace::format_timestamp(
    const std::chrono::time_point<std::chrono::system_clock> &time_point,
    const std::string &raw_fmt,
    bool utc)
{
  static const auto nsec_regex = std::regex("%k");
  static const auto usec_regex = std::regex("%f");
  static const auto msec_regex = std::regex("%l");
  time_t time = std::chrono::system_clock::to_time_t(time_point);
  auto ns = (time_point - std::chrono::floor<std::chrono::seconds>(time_point))
                .count();

  if (!time) {
    return "(?)";
  }

  // Calculate and localize timestamp
  struct tm tmp;
  if (utc) {
    if (!gmtime_r(&time, &tmp)) {
      LOG(ERROR) << "gmtime_r: " << strerror(errno);
      return "(?)";
    }
  } else {
    if (!localtime_r(&time, &tmp)) {
      LOG(ERROR) << "localtime_r: " << strerror(errno);
      return "(?)";
    }
  }

  // Process strftime() format string extensions
  std::chrono::nanoseconds ns_rem(ns);
  char nsecs_buf[10];
  snprintf(nsecs_buf, sizeof(nsecs_buf), "%09" PRIu64, ns_rem.count());
  char usecs_buf[7];
  snprintf(
      usecs_buf,
      sizeof(usecs_buf),
      "%06" PRIu64,
      std::chrono::duration_cast<std::chrono::microseconds>(ns_rem).count());
  char msecs_buf[4];
  snprintf(
      msecs_buf,
      sizeof(msecs_buf),
      "%03" PRIu64,
      std::chrono::duration_cast<std::chrono::milliseconds>(ns_rem).count());
  auto fmt = std::regex_replace(raw_fmt, usec_regex, usecs_buf);
  fmt = std::regex_replace(fmt, nsec_regex, nsecs_buf);
  fmt = std::regex_replace(fmt, msec_regex, msecs_buf);

  const auto timestr_size = config_->max_strlen;
  std::string timestr(timestr_size, '\0');
  size_t timestr_len = strftime(
      timestr.data(), timestr_size, fmt.c_str(), &tmp);
  if (timestr_len == 0) {
    LOG(ERROR) << "strftime returned 0";
    return "(?)";
  }

  // Fit return value to formatted length
  timestr.resize(timestr_len);
  return timestr;
}

std::string BPFtrace::resolve_ksym(uint64_t addr)
{
  auto syms = resolve_ksym_stack(addr, false, false, false);
  assert(syms.size() == 1);
  return syms.front();
}

std::vector<std::string> BPFtrace::resolve_ksym_stack(uint64_t addr,
                                                      bool show_offset,
                                                      bool perf_mode,
                                                      bool show_debug_info)
{
  return ksyms_.resolve(addr, show_offset, perf_mode, show_debug_info);
}

uint64_t BPFtrace::resolve_kname(const std::string &name) const
{
  uint64_t addr = 0;
  std::string file_name = "/proc/kallsyms";

  std::ifstream file(file_name);
  if (file.fail()) {
    LOG(ERROR) << strerror(errno) << ": " << file_name;
    return addr;
  }

  std::string line;

  while (std::getline(file, line) && addr == 0) {
    auto tokens = util::split_string(line, ' ');

    if (name == tokens[2]) {
      addr = read_address_from_output(line);
      break;
    }
  }

  file.close();

  return addr;
}

static int sym_resolve_callback(const char *name,
                                uint64_t addr,
                                uint64_t size,
                                void *payload)
{
  auto *sym = static_cast<struct symbol *>(payload);
  if (!strcmp(name, sym->name.c_str())) {
    sym->address = addr;
    sym->size = size;
    return -1;
  }
  return 0;
}

int BPFtrace::resolve_uname(const std::string &name,
                            struct symbol *sym,
                            const std::string &path) const
{
  sym->name = name;
  struct bcc_symbol_option option;
  memset(&option, 0, sizeof(option));
  option.use_symbol_type = (1 << STT_OBJECT | 1 << STT_FUNC |
                            1 << STT_GNU_IFUNC);

  return bcc_elf_foreach_sym(path.c_str(), sym_resolve_callback, &option, sym);
}

std::string BPFtrace::resolve_mac_address(const char *mac_addr) const
{
  const size_t SIZE = 18;
  char addr[SIZE];
  snprintf(addr,
           SIZE,
           "%02X:%02X:%02X:%02X:%02X:%02X",
           mac_addr[0],
           mac_addr[1],
           mac_addr[2],
           mac_addr[3],
           mac_addr[4],
           mac_addr[5]);
  return addr;
}

std::string BPFtrace::resolve_cgroup_path(uint64_t cgroup_path_id,
                                          uint64_t cgroup_id) const
{
  auto paths = util::get_cgroup_paths(
      cgroup_id, resources.cgroup_path_args[cgroup_path_id]);
  std::stringstream result;
  for (auto &pair : paths) {
    if (pair.second.empty())
      continue;
    result << pair.first << ":" << pair.second << ",";
  }
  return result.str().substr(0, result.str().size() - 1);
}

uint64_t BPFtrace::read_address_from_output(std::string output)
{
  std::string first_word = output.substr(0, output.find(" "));
  return std::stoull(first_word, nullptr, 16);
}

static std::string resolve_inetv4(const char *inet)
{
  char addr_cstr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, inet, addr_cstr, INET_ADDRSTRLEN);
  return addr_cstr;
}

static std::string resolve_inetv6(const char *inet)
{
  char addr_cstr[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, inet, addr_cstr, INET6_ADDRSTRLEN);
  return addr_cstr;
}

std::string BPFtrace::resolve_inet(int af, const char *inet) const
{
  std::string addrstr;
  switch (af) {
    case AF_INET:
      addrstr = resolve_inetv4(inet);
      break;
    case AF_INET6:
      addrstr = resolve_inetv6(inet);
      break;
  }

  // TODO(mmarchini): handle inet_ntop errors
  return addrstr;
}

std::string BPFtrace::resolve_usym(uint64_t addr, int32_t pid, int32_t probe_id)
{
  auto syms = resolve_usym_stack(addr, pid, probe_id, false, false, false);
  assert(syms.size() == 1);
  return syms.front();
}

std::vector<std::string> BPFtrace::resolve_usym_stack(uint64_t addr,
                                                      int32_t pid,
                                                      int32_t probe_id,
                                                      bool show_offset,
                                                      bool perf_mode,
                                                      bool show_debug_info)
{
  std::string pid_exe;
  auto res = util::get_pid_exe(pid);
  if (res) {
    pid_exe = *res;
  } else if (probe_id != -1) {
    // sometimes program cannot be determined from PID, typically when the
    // process does not exist anymore; in that case, try to get program name
    // from probe
    // note: this fails if the probe contains a wildcard, since the probe id
    // is not generated per match
    auto probe_full = resolve_probe(probe_id);
    if (probe_full.find(',') == std::string::npos &&
        !util::has_wildcard(probe_full)) {
      // only find program name for probes that contain one program name,
      // to avoid incorrect symbol resolutions
      size_t start = probe_full.find(':') + 1;
      size_t end = probe_full.find(':', start);
      pid_exe = probe_full.substr(start, end - start);
    }
  }
  return usyms_.resolve(
      addr, pid, pid_exe, show_offset, perf_mode, show_debug_info);
}

std::string BPFtrace::resolve_probe(uint64_t probe_id) const
{
  assert(probe_id < resources.probe_ids.size());
  return resources.probe_ids[probe_id];
}

const util::FuncsModulesMap &BPFtrace::get_traceable_funcs() const
{
  if (traceable_funcs_.empty())
    traceable_funcs_ = util::parse_traceable_funcs();

  return traceable_funcs_;
}

const util::FuncsModulesMap &BPFtrace::get_raw_tracepoints() const
{
  if (raw_tracepoints_.empty())
    raw_tracepoints_ = util::parse_rawtracepoints();

  return raw_tracepoints_;
}

bool BPFtrace::is_traceable_func(const std::string &func_name) const
{
  const auto &funcs = get_traceable_funcs();
  return funcs.contains(func_name);
}

int BPFtrace::resume_tracee(pid_t tracee_pid)
{
  return ::kill(tracee_pid, SIGCONT);
}

std::unordered_set<std::string> BPFtrace::get_func_modules(
    const std::string &func_name) const
{
  const auto &funcs = get_traceable_funcs();
  auto mod = funcs.find(func_name);
  return mod != funcs.end() ? mod->second : std::unordered_set<std::string>();
}

std::unordered_set<std::string> BPFtrace::get_raw_tracepoint_modules(
    const std::string &name) const
{
  const auto &rts = get_raw_tracepoints();
  auto mod = rts.find(name);
  return mod != rts.end() ? mod->second : std::unordered_set<std::string>();
}

const std::optional<struct stat> &BPFtrace::get_pidns_self_stat() const
{
  static std::optional<struct stat> pidns = []() -> std::optional<struct stat> {
    struct stat s;
    if (::stat("/proc/self/ns/pid", &s)) {
      if (errno == ENOENT)
        return std::nullopt;
      throw std::runtime_error(
          std::string("Failed to stat /proc/self/ns/pid: ") +
          std::strerror(errno));
    }
    return s;
  }();

  return pidns;
}

Dwarf *BPFtrace::get_dwarf(const std::string &filename)
{
  auto dwarf = dwarves_.find(filename);
  if (dwarf == dwarves_.end()) {
    dwarf =
        dwarves_.emplace(filename, Dwarf::GetFromBinary(this, filename)).first;
  }
  return dwarf->second.get();
}

Dwarf *BPFtrace::get_dwarf(const ast::AttachPoint &attachpoint)
{
  auto probe_type = probetype(attachpoint.provider);
  if (probe_type != ProbeType::uprobe && probe_type != ProbeType::uretprobe)
    return nullptr;

  return get_dwarf(attachpoint.target);
}

int BPFtrace::create_pcaps()
{
  for (auto arg : resources.skboutput_args_) {
    auto file = std::get<0>(arg);

    if (pcap_writers_.contains(file)) {
      return 0;
    }

    auto writer = std::make_unique<PCAPwriter>();

    if (!writer->open(file))
      return -1;

    pcap_writers_[file] = std::move(writer);
  }

  return 0;
}

void BPFtrace::close_pcaps()
{
  for (auto &writer : pcap_writers_) {
    writer.second->close();
  }
}

bool BPFtrace::write_pcaps(uint64_t id, uint64_t ns, const OpaqueValue &pkt)
{
  if (boottime_) {
    ns = (boottime_->tv_sec * 1e9) + (boottime_->tv_nsec + ns);
  }

  auto file = std::get<0>(resources.skboutput_args_.at(id));
  auto &writer = pcap_writers_.at(file);

  return writer->write(ns, pkt.data(), pkt.size());
}

void BPFtrace::parse_module_btf(const std::set<std::string> &modules)
{
  btf_->load_module_btfs(modules);
}

bool BPFtrace::has_btf_data() const
{
  return btf_->has_data();
}

// Retrieves the list of kernel modules for all attachpoints. Will be used to
// identify modules whose BTF we need to parse.
// Currently, this is useful for fentry/fexit, k(ret)probes, tracepoints,
// and raw tracepoints
std::set<std::string> BPFtrace::list_modules(const ast::ASTContext &ctx)
{
  std::set<std::string> modules;
  for (const auto &probe : ctx.root->probes) {
    for (const auto &ap : probe->attach_points) {
      auto probe_type = probetype(ap->provider);
      if (probe_type == ProbeType::fentry || probe_type == ProbeType::fexit ||
          probe_type == ProbeType::rawtracepoint ||
          probe_type == ProbeType::kprobe ||
          probe_type == ProbeType::kretprobe) {
        // Force module name into listing
        bool clear_target;
        if (ap->target.empty()) {
          ap->target = "*";
          clear_target = true;
        } else {
          clear_target = false;
        }

        for (std::string match : probe_matcher_->get_matches_for_ap(*ap)) {
          auto module = util::erase_prefix(match);
          modules.insert(module);
        }

        if (clear_target)
          ap->target.clear();
      } else if (probe_type == ProbeType::tracepoint) {
        // For now, we support this for a single target only since tracepoints
        // need dumping of C definitions BTF and that is not available for
        // multiple modules at once.
        modules.insert(ap->target);
      }
    }
  }
  return modules;
}

} // namespace bpftrace
