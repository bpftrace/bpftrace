#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "bpfprogram.h"
#include "providers/perf.h"
#include "util/int_parser.h"

namespace bpftrace::providers {

class PerfEventAttachPoint : public SimpleAttachPoint {
public:
  PerfEventAttachPoint(std::string orig_name,
                       uint64_t perf_type,
                       uint64_t event_type,
                       uint64_t freq)
      : SimpleAttachPoint(std::move(orig_name)),
        perf_type(perf_type),
        event_type(event_type),
        freq(freq) {};

  bpf_prog_type prog_type() const override
  {
    return BPF_PROG_TYPE_PERF_EVENT;
  }

  const uint64_t perf_type;
  const uint64_t event_type;
  const uint64_t freq;
};

class PerfAttachedProbe : public AttachedProbe {
public:
  PerfAttachedProbe(struct bpf_link *link,
                    AttachPointList &&attach_points,
                    int perf_event_fd)
      : AttachedProbe(link, std::move(attach_points)),
        perf_event_fd_(perf_event_fd) {};

private:
  util::FD perf_event_fd_;
};

struct PerfEvent {
  std::string path;
  std::string alias;
  uint64_t perf_type;
  uint64_t event_type;
  uint64_t freq;
};

const std::vector<PerfEvent> perf_events = {
  { .path = "alignment-faults",
    .alias = "",
    .perf_type = PERF_TYPE_SOFTWARE,
    .event_type = PERF_COUNT_SW_ALIGNMENT_FAULTS,
    .freq = 1 },
  { .path = "bpf-output",
    .alias = "",
    .perf_type = PERF_TYPE_SOFTWARE,
    .event_type = PERF_COUNT_SW_BPF_OUTPUT,
    .freq = 1 },
  { .path = "context-switches",
    .alias = "cs",
    .perf_type = PERF_TYPE_SOFTWARE,
    .event_type = PERF_COUNT_SW_CONTEXT_SWITCHES,
    .freq = 1000 },
  { .path = "cpu-clock",
    .alias = "cpu",
    .perf_type = PERF_TYPE_SOFTWARE,
    .event_type = PERF_COUNT_SW_CPU_CLOCK,
    .freq = 1000000 },
  { .path = "cpu-migrations",
    .alias = "",
    .perf_type = PERF_TYPE_SOFTWARE,
    .event_type = PERF_COUNT_SW_CPU_MIGRATIONS,
    .freq = 1 },
  { .path = "dummy",
    .alias = "",
    .perf_type = PERF_TYPE_SOFTWARE,
    .event_type = PERF_COUNT_SW_DUMMY,
    .freq = 1 },
  { .path = "emulation-faults",
    .alias = "",
    .perf_type = PERF_TYPE_SOFTWARE,
    .event_type = PERF_COUNT_SW_EMULATION_FAULTS,
    .freq = 1 },
  { .path = "major-faults",
    .alias = "",
    .perf_type = PERF_TYPE_SOFTWARE,
    .event_type = PERF_COUNT_SW_PAGE_FAULTS_MAJ,
    .freq = 1 },
  { .path = "minor-faults",
    .alias = "",
    .perf_type = PERF_TYPE_SOFTWARE,
    .event_type = PERF_COUNT_SW_PAGE_FAULTS_MIN,
    .freq = 100 },
  { .path = "page-faults",
    .alias = "faults",
    .perf_type = PERF_TYPE_SOFTWARE,
    .event_type = PERF_COUNT_SW_PAGE_FAULTS,
    .freq = 100 },
  { .path = "task-clock",
    .alias = "",
    .perf_type = PERF_TYPE_SOFTWARE,
    .event_type = PERF_COUNT_SW_TASK_CLOCK,
    .freq = 1 },
  { .path = "backend-stalls",
    .alias = "",
    .perf_type = PERF_TYPE_HARDWARE,
    .event_type = PERF_COUNT_HW_STALLED_CYCLES_BACKEND,
    .freq = 1000000 },
  { .path = "branch-instructions",
    .alias = "branches",
    .perf_type = PERF_TYPE_HARDWARE,
    .event_type = PERF_COUNT_HW_BRANCH_INSTRUCTIONS,
    .freq = 100000 },
  { .path = "branch-misses",
    .alias = "",
    .perf_type = PERF_TYPE_HARDWARE,
    .event_type = PERF_COUNT_HW_BRANCH_MISSES,
    .freq = 100000 },
  { .path = "bus-cycles",
    .alias = "",
    .perf_type = PERF_TYPE_HARDWARE,
    .event_type = PERF_COUNT_HW_BUS_CYCLES,
    .freq = 100000 },
  { .path = "cache-misses",
    .alias = "",
    .perf_type = PERF_TYPE_HARDWARE,
    .event_type = PERF_COUNT_HW_CACHE_MISSES,
    .freq = 1000000 },
  { .path = "cache-references",
    .alias = "",
    .perf_type = PERF_TYPE_HARDWARE,
    .event_type = PERF_COUNT_HW_CACHE_REFERENCES,
    .freq = 1000000 },
  { .path = "cpu-cycles",
    .alias = "cycles",
    .perf_type = PERF_TYPE_HARDWARE,
    .event_type = PERF_COUNT_HW_CPU_CYCLES,
    .freq = 1000000 },
  { .path = "frontend-stalls",
    .alias = "",
    .perf_type = PERF_TYPE_HARDWARE,
    .event_type = PERF_COUNT_HW_STALLED_CYCLES_FRONTEND,
    .freq = 1000000 },
  { .path = "instructions",
    .alias = "",
    .perf_type = PERF_TYPE_HARDWARE,
    .event_type = PERF_COUNT_HW_INSTRUCTIONS,
    .freq = 1000000 },
  { .path = "ref-cycles",
    .alias = "",
    .perf_type = PERF_TYPE_HARDWARE,
    .event_type = PERF_COUNT_HW_REF_CPU_CYCLES,
    .freq = 1000000 }
};

Result<AttachPointList> PerfProvider::parse(
    const std::string &str,
    [[maybe_unused]] BtfLookup &btf,
    [[maybe_unused]] std::optional<int> pid) const
{
  std::optional<uint64_t> param;
  std::string event = str;
  auto colon_pos = event.find(':');
  if (colon_pos != std::string::npos) {
    std::string freq_str = event.substr(colon_pos + 1);
    event = event.substr(0, colon_pos);
    auto ok = util::to_uint(freq_str);
    if (!ok) {
      return ok.takeError();
    }
    param = *ok;
  }

  // Find the relevant event, if it exists.
  for (const auto &perf_event : perf_events) {
    if (event == perf_event.path || event == perf_event.alias) {
      uint64_t freq = perf_event.freq;
      if (param.has_value()) {
        freq = *param; // User-provided.
      }
      return make_list<PerfEventAttachPoint>(
          str, perf_event.perf_type, perf_event.event_type, freq);
    }
  }

  return make_error<ParseError>(this, str, "unknown perf event");
}

Result<AttachedProbeList> PerfProvider::attach_single(
    std::unique_ptr<AttachPoint> &&attach_point,
    const BpfProgram &prog,
    [[maybe_unused]] std::optional<int> pid) const
{
  auto &perf_attach_point = attach_point->as<PerfEventAttachPoint>();
  struct perf_event_attr attr = {};
  attr.type = perf_attach_point.perf_type;
  attr.size = sizeof(struct perf_event_attr);
  attr.config = perf_attach_point.event_type;

  pid_t perf_pid = -1;
  int perf_cpu = 0;
  if (pid) {
    perf_pid = *pid; // Monitor this specific pid.
    perf_cpu = -1;   // All CPUs, but only this pid.
  }

  int perf_event_fd = syscall(__NR_perf_event_open,
                              &attr,
                              perf_pid,
                              perf_cpu,
                              -1,
                              PERF_FLAG_FD_CLOEXEC);
  if (perf_event_fd < 0) {
    return make_error<SystemError>("failed to open perf event for perf probe");
  }

  // Use libbpf to attach the hardware event.
  auto *link = bpf_program__attach_perf_event(prog.bpf_prog(), perf_event_fd);
  if (!link) {
    close(perf_event_fd);
    return make_error<AttachError>(this,
                                   std::move(attach_point),
                                   "failed to attach perf event");
  }

  return make_list<PerfAttachedProbe>(link,
                                      wrap_list(std::move(attach_point)),
                                      perf_event_fd);
}

} // namespace bpftrace::providers

CEREAL_REGISTER_TYPE(bpftrace::providers::PerfEventAttachPoint)
CEREAL_REGISTER_POLYMORPHIC_RELATION(bpftrace::providers::SimpleAttachPoint,
                                     bpftrace::providers::PerfEventAttachPoint)
