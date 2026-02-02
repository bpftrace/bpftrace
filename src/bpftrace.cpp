#include "types_format.h"
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
#include <cmath>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <glob.h>
#include <iomanip>
#include <iostream>
#include <ranges>
#include <regex>
#include <sstream>
#include <sys/epoll.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef HAVE_LIBSYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "ast/context.h"
#include "async_action.h"
#include "attached_probe.h"
#include "bpfmap.h"
#include "bpfprogram.h"
#include "bpftrace.h"
#include "btf.h"
#include "log.h"
#include "output/capture.h"
#include "output/discard.h"
#include "output/text.h"
#include "scopeguard.h"
#include "util/bpf_names.h"
#include "util/cgroup.h"
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

static void set_rlimit_nofile(size_t num_probes, size_t num_maps)
{
  // 3 fds per probe + maps + buffer for things like scratch maps
  size_t needed_fd_count = (num_probes * 3) + num_maps + 50;

  rlimit current_limit;
  if (getrlimit(RLIMIT_NOFILE, &current_limit) != 0) {
    LOG(V1) << "Could not get current RLIMIT_NOFILE";
    return;
  }

  if (current_limit.rlim_cur >= needed_fd_count) {
    return;
  }

  struct rlimit rl = {};
  int err;

  rl.rlim_max = needed_fd_count;
  rl.rlim_cur = needed_fd_count;
  err = setrlimit(RLIMIT_NOFILE, &rl);
  if (err)
    LOG(WARNING)
        << std::strerror(err) << ": couldn't set RLIMIT_NOFILE for "
        << "bpftrace. If your program is not loading, you can try increasing"
        << "\"ulimit -n\" to fix the problem";
}

BPFtrace::~BPFtrace()
{
  close_pcaps();
}

Probe BPFtrace::generate_probe(const ast::AttachPoint &ap,
                               const ast::Probe &p,
                               ast::ExpansionType expansion,
                               std::set<std::string> expanded_funcs)
{
  Probe probe;
  probe.path = ap.target;
  probe.attach_point = ap.func;
  probe.type = probetype(ap.provider);
  probe.log_size = config_->log_size;
  probe.ns = ap.ns;
  probe.name = ap.name();
  probe.freq = ap.freq;
  probe.address = ap.address;
  probe.func_offset = ap.func_offset;
  probe.loc = 0;
  probe.index = p.index();
  probe.len = ap.len;
  probe.mode = ap.mode;
  probe.pin = ap.pin;
  probe.is_session = expansion == ast::ExpansionType::SESSION;
  probe.funcs = std::move(expanded_funcs);
  probe.bpf_prog_id = ap.bpf_prog_id;
  return probe;
}

int BPFtrace::add_probe(const ast::AttachPoint &ap,
                        const ast::Probe &p,
                        ast::ExpansionType expansion,
                        std::set<std::string> expanded_funcs)
{
  auto type = probetype(ap.provider);
  auto probe = generate_probe(ap, p, expansion, std::move(expanded_funcs));

  if (ap.provider == "begin") {
    resources.begin_probes.emplace_back(std::move(probe));
  } else if (ap.provider == "end") {
    resources.end_probes.emplace_back(std::move(probe));
  } else if (ap.provider == "test") {
    resources.test_probes.emplace_back(std::move(probe));
  } else if (ap.provider == "bench") {
    resources.benchmark_probes.emplace_back(std::move(probe));
  } else if (ap.provider == "self") {
    if (ap.target == "signal") {
      resources.signal_probes.emplace_back(std::move(probe));
    }
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
  return resources.num_probes();
}

void BPFtrace::request_finalize()
{
  finalize_ = true;
  attached_probes_.clear();
  if (child_) {
    auto result = child_->terminate();
    if (!result)
      consumeError(result.takeError());
  }
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

void event_printer(void *cb_cookie, void *raw_data, int size)
{
  auto *ctx = static_cast<PerfEventContext *>(cb_cookie);

  // N.B. This will copy the value into its own buffer, potentially allocating
  // and freeing a new chunk if it is larger than a single word. This is
  // guaranteed to be aligned.
  auto data = OpaqueValue::alloc(size, [&](char *data) {
    memcpy(data, raw_data, size);
  });

  // Ignore the remaining events if event_printer is called during
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
  } else {
    LOG(BUG) << "Unknown printf_id: " << static_cast<int64_t>(printf_id);
  }
}

int ringbuf_printer(void *cb_cookie, void *data, size_t size)
{
  event_printer(cb_cookie, data, size);
  return 0;
}

void skb_output_printer(void *ctx,
                        [[maybe_unused]] int cpu,
                        void *data,
                        __u32 size)
{
  event_printer(ctx, data, size);
}

void skb_output_lost(void *ctx, [[maybe_unused]] int cpu, __u64 cnt)
{
  auto *perf_ctx = static_cast<PerfEventContext *>(ctx);
  perf_ctx->output.lost_events(cnt);
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

Result<std::unique_ptr<AttachedProbe>> BPFtrace::attach_probe(
    Probe &probe,
    const BpfBytecode &bytecode)
{
  const auto &program = bytecode.getProgramForProbe(probe);
  std::optional<pid_t> pid = child_ ? std::make_optional(child_->pid())
                                    : this->pid();

  auto ap = AttachedProbe::make(probe, program, pid, safe_mode_);
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
    case ProbeType::test:
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

  set_rlimit_nofile(resources.num_probes(), resources.maps_info.size());

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

  int num_begin_attached = 0;
  int num_end_attached = 0;
  int num_signal_attached = 0;
  int num_test_attached = 0;
  int num_benchmark_attached = 0;

  for (const auto &begin_probe : resources.begin_probes) {
    auto &begin_prog = bytecode_.getProgramForProbe(begin_probe);
    if (::bpf_prog_test_run_opts(begin_prog.fd(), nullptr))
      return -1;

    LOG(V1) << "Attaching 'begin' probe";
    ++num_begin_attached;
  }
  num_end_attached += resources.end_probes.size();

  int rval = 0; // Used for return below.

  if (run_tests_ || run_benchmarks_) {
    if (run_tests_) {
      std::vector<std::string> all_tests;
      std::vector<bool> all_passed;
      for (auto &probe : resources.test_probes) {
        all_tests.emplace_back(probe.path);
      }

      for (size_t index = 0; index < resources.test_probes.size(); index++) {
        ++num_test_attached;
        auto &probe = resources.test_probes[index];
        auto &test_prog = bytecode_.getProgramForProbe(probe);

        // We swap our output for something that will capture the
        // result of executing this single test. `poll_output` should
        // be called after each test, and `ss.str("")` to reset the
        // output (or used as required).
        std::stringstream ss;
        auto text_output = std::make_unique<output::TextOutput>(ss, ss);
        auto capture = std::make_unique<output::CaptureOutput>(*text_output);
        handlers.change_output(*capture);

        // See below; we must provide sufficient data.
        constexpr size_t ETH_HLEN = 14;
        char data_in[ETH_HLEN];
        DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts);
        opts.data_in = data_in;
        opts.data_size_in = ETH_HLEN;
        opts.repeat = 1;
        if (auto ret = ::bpf_prog_test_run_opts(test_prog.fd(), &opts)) {
          LOG(ERROR) << "bpf_prog_test_run_opts failed: " << ret;
          return -1;
        }

        // See above; ensure the output is flushed.
        poll_output(*capture, true);
        bool passed = opts.retval == 0 && exit_code == 0 &&
                      capture->error_count == 0;
        all_passed.push_back(passed);
        out.test_result(all_tests,
                        index,
                        std::chrono::nanoseconds(opts.duration),
                        all_passed,
                        ss.str());

        // Override the return value.
        if (rval == 0 && !passed) {
          rval = 1;
        }
        exit_code = 0; // Reset for all tests.
      }

      // Return the original output.
      handlers.change_output(out);
    } else if (run_benchmarks_) {
      std::vector<std::string> all_benches;
      for (auto &probe : resources.benchmark_probes) {
        all_benches.emplace_back(probe.path);
      }

      for (size_t index = 0; index < resources.benchmark_probes.size();
           index++) {
        ++num_benchmark_attached;
        auto &probe = resources.benchmark_probes[index];
        auto &benchmark_prog = bytecode_.getProgramForProbe(probe);

        // Increase opts.repeat until we reach at least 1ms of run time. We
        // double the repeat time each instance, so each probe should take
        // a few milliseconds at most (plus loading time, etc).
        size_t iters = 1;
        while (true) {
          // Benchmarks have all output suppressed.
          auto discard = std::make_unique<output::DiscardOutput>();
          auto capture = std::make_unique<output::CaptureOutput>(*discard);
          handlers.change_output(*capture);

          // Note: on newer kernels you must provide a data_in buffer at least
          // ETH_HLEN bytes long to make sure input validation works for
          // opts. Otherwise, bpf_prog_test_run_opts will return -EINVAL for
          // BPF_PROG_TYPE_XDP.
          //
          // https://github.com/torvalds/linux/commit/6b3d638ca897e099fa99bd6d02189d3176f80a47
          constexpr size_t ETH_HLEN = 14;
          char data_in[ETH_HLEN];
          DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts);
          opts.data_in = data_in;
          opts.data_size_in = ETH_HLEN;
          opts.repeat = iters;

          if (auto ret = ::bpf_prog_test_run_opts(benchmark_prog.fd(), &opts)) {
            LOG(ERROR) << "bpf_prog_test_run_opts failed: " << ret;
            return -1;
          }

          poll_output(*capture, true);
          // Allow skipping benchmarks by returning 1.
          if (exit_code == 0 && opts.retval != 0) {
            break;
          }
          // Did we run for enough time?
          auto total = std::chrono::nanoseconds(opts.duration) * iters;
          if (total < std::chrono::microseconds(1)) {
            iters *= 10'00;
            continue;
          }
          if (total < std::chrono::microseconds(10)) {
            iters *= 100;
            continue;
          }
          if (total < std::chrono::microseconds(100)) {
            iters *= 10;
            continue;
          }
          if (total < std::chrono::milliseconds(1)) {
            iters *= 2;
            continue;
          }

          // We don't include any benchmark results that have failed, but
          // they are allowed to skip by returning 1. If they explicitly
          // use errorf or something similar, then we fail the run.
          if (exit_code != 0 || capture->error_count != 0) {
            LOG(ERROR) << "Benchmark '" << probe.path << "' failed.";
            rval = 1;
            exit_code = 0; // Always reset for tests.
            break;
          }

          out.benchmark_result(all_benches,
                               index,
                               std::chrono::nanoseconds(opts.duration),
                               iters);
          handlers.change_output(out);
          break;
        }
      }
    }
  } else {
    for (auto &probe : resources.signal_probes) {
      auto &sig_prog = bytecode_.getProgramForProbe(probe);
      sigusr1_prog_fds_.emplace_back(sig_prog.fd());
      ++num_signal_attached;
    }

    if (child_ && has_usdt_) {
      auto result = child_->run(true);
      if (!result) {
        LOG(ERROR) << "Failed to setup child: " << result.takeError();
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
      return rval;
    }

    // Kick the child to execute the command.
    if (child_) {
      if (has_usdt_) {
        auto result = child_->resume();
        if (!result) {
          LOG(ERROR) << "Failed to run child: " << result.takeError();
          return -1;
        }
      } else {
        auto result = child_->run();
        if (!result) {
          LOG(ERROR) << "Failed to run child: " << result.takeError();
          return -1;
        }
      }
    }
  }

  size_t num_attached = 0;

  for (auto &ap : attached_probes_) {
    num_attached += ap->probe_count();
  }

  auto total_attached = num_attached + num_begin_attached + num_end_attached +
                        num_signal_attached + num_test_attached +
                        num_benchmark_attached;

  if (total_attached == 0) {
    // Provide some helpful hints, there if there are test or benchmark probes
    // defined, they won't be attached unless the appropriate mode is set.
    if (!resources.test_probes.empty()) {
      LOG(ERROR) << "No probes attached; use --test to run test probes.";
    } else if (!resources.benchmark_probes.empty()) {
      LOG(ERROR) << "No probes attached; use --bench to run benchmark probes.";
    } else {
      LOG(ERROR) << "Attachment failed for all probes.";
    }
    return -1;
  }

  if (!bt_quiet && !run_tests_ && !run_benchmarks_) {
    out.attached_probes(total_attached);
  }

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
    bool should_drain = (num_begin_attached > 0 || num_end_attached > 0 ||
                         run_tests_ || run_benchmarks_) &&
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
  // event_printer() can ignore the `end` events.
  finalize_ = false;
  exitsig_recv = false;

  for (const auto &end_probe : resources.end_probes) {
    auto &end_prog = bytecode_.getProgramForProbe(end_probe);
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

  // Indicate that we are done the main loop.
  out.end();

  // Print maps if needed (true by default).
  if (!err && !run_tests_ && !run_benchmarks_ && !dry_run &&
      config_->print_maps_on_exit) {
    for (const auto &[_, map] : bytecode_.maps()) {
      if (!map.is_printable())
        continue;
      auto res = format(*this, c_definitions, map);
      if (!res) {
        std::cerr << "Error printing map: " << res.takeError();
        continue;
      }
      out.map(map.name(), *res);
    }
  }

  return rval;
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
  auto map = bytecode_.getMap(MapType::PerfEvent);

  auto num_pages = get_buffer_pages_per_cpu();
  if (!num_pages) {
    LOG(ERROR) << num_pages.takeError();
    return -1;
  }

  skb_perfbuf_ = perf_buffer__new(map.fd(),
                                  *num_pages,
                                  &skb_output_printer,
                                  &skb_output_lost,
                                  ctx,
                                  nullptr);

  if (skb_perfbuf_ == nullptr) {
    LOG(ERROR) << "Failed to open perf buffer";
    return -1;
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
    perf_buffer__free(skb_perfbuf_);
}

void BPFtrace::poll_output(output::Output &out, bool drain)
{
  int ready;
  bool poll_skboutput = resources.using_skboutput;
  bool do_poll_ringbuf = true;
  auto should_retry = [](int ready) {
    // epoll_wait will set errno to EINTR if an interrupt received, it is
    // retryable if not caused by SIGINT. ring_buffer__poll does not set
    // errno, we will keep retrying till SIGINT.
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

  while (true) {
    if (poll_skboutput) {
      ready = perf_buffer__poll(skb_perfbuf_, timeout_ms);
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

std::string BPFtrace::get_stack(uint64_t nr_stack_frames,
                                const OpaqueValue &raw_stack,
                                int32_t pid,
                                int32_t probe_id,
                                bool ustack,
                                StackType stack_type,
                                int indent)
{
  std::ostringstream stack;
  std::string padding(indent, ' ');

  stack << "\n";
  for (uint64_t i = 0; i < nr_stack_frames; ++i) {
    auto addr = raw_stack.bitcast<uint64_t>(i);
    if (stack_type.mode == StackMode::raw) {
      stack << std::hex << addr << std::endl;
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

    for (auto const &sym : syms) {
      switch (stack_type.mode) {
        case StackMode::bpftrace:
          stack << padding << sym << std::endl;
          break;
        case StackMode::perf:
          stack << "\t" << std::hex << addr << std::dec << " " << sym
                << std::endl;
          break;
        case StackMode::raw:
        case StackMode::build_id:
          LOG(BUG)
              << "StackMode::raw or build_id should have been processed before "
                 "symbolication.";
          break;
      }
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
      t += std::chrono::duration_cast<std::chrono::system_clock::duration>(
          std::chrono::nanoseconds(boottime_->tv_nsec));
    }
  }

  t += std::chrono::duration_cast<std::chrono::system_clock::duration>(
      std::chrono::nanoseconds(nsecs));
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

int BPFtrace::resume_tracee(pid_t tracee_pid)
{
  return ::kill(tracee_pid, SIGCONT);
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

uint64_t find_closest_power_of_2(uint64_t n)
{
  double log_val = log2(n);
  auto low_end = static_cast<uint64_t>(pow(2, floor(log_val)));
  auto high_end = static_cast<uint64_t>(pow(2, ceil(log_val)));

  if (n - low_end <= high_end - n) {
    return low_end;
  } else {
    return high_end;
  }
}

Result<uint64_t> BPFtrace::get_buffer_pages(bool per_cpu) const
{
  if (config_->perf_rb_pages) {
    auto pages = config_->perf_rb_pages;
    if (!per_cpu) {
      // We want at least one page per cpu
      if (pages < static_cast<uint64_t>(ncpus_)) {
        return ncpus_;
      }
      return pages;
    }

    double res = static_cast<double>(pages) / ncpus_;
    pages = static_cast<uint64_t>(std::ceil(res));
    return find_closest_power_of_2(pages);
  }
  auto available_mem_kb = util::get_available_mem_kb();
  if (!available_mem_kb) {
    return available_mem_kb;
  }

  static uint64_t ceiling = 16544;
  static uint64_t floor = 256;
  uint64_t max = std::min(*available_mem_kb, ceiling);
  uint64_t amount_bytes = std::max(max, floor) * 1024;
  if (per_cpu) {
    amount_bytes /= ncpus_;
  }
  return find_closest_power_of_2(amount_bytes / sysconf(_SC_PAGE_SIZE));
}

Result<uint64_t> BPFtrace::get_buffer_pages_per_cpu() const
{
  return get_buffer_pages(true);
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
std::set<std::string> BPFtrace::list_modules(const ast::ASTContext &ctx,
                                             ProbeMatcher &probe_matcher)
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

        for (std::string match : probe_matcher.get_matches_for_ap(*ap)) {
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
