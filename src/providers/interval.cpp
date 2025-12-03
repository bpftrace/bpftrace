#include <bpf/libbpf.h>
#include <chrono>
#include <linux/perf_event.h>
#include <sstream>
#include <sys/syscall.h>
#include <unistd.h>

#include "bpfprogram.h"
#include "providers/interval.h"
#include "util/int_parser.h"
#include "util/strings.h"
#include "util/time.h"

namespace bpftrace::providers {

class IntervalAttachPoint : public AttachPoint {
public:
  IntervalAttachPoint(uint64_t interval) : interval(interval) {};

  std::string name() const override
  {
    std::stringstream ss;
    auto [unit, scale] = util::duration_str(std::chrono::nanoseconds(interval));
    // This uses the new literal syntax, e.g. `i:1s`.
    ss << interval / scale << unit;
    return ss.str();
  }

  bpf_prog_type prog_type() const override
  {
    return BPF_PROG_TYPE_PERF_EVENT;
  }

  template <class Archive>
  void serialize([[maybe_unused]] Archive &ar)
  {
    ar(interval);
  }

  uint64_t interval; // interval time in nanoseconds.
};

class IntervalAttachedProbe : public AttachedProbe {
public:
  IntervalAttachedProbe(
      struct bpf_link *link,
      std::vector<std::unique_ptr<AttachPoint>> &&attach_points,
      int perf_event_fd)
      : AttachedProbe(link, std::move(attach_points)),
        perf_event_fd_(perf_event_fd) {};

private:
  util::FD perf_event_fd_;
};

Result<AttachPointList> IntervalProvider::parse(
    const std::string &str,
    [[maybe_unused]] BtfLookup &btf,
    [[maybe_unused]] std::optional<int> pid) const
{
  auto parts = util::split_string(str, ':');

  uint64_t scale = 1;
  std::string value;
  if (parts.size() == 1) {
    value = parts[0];
  } else if (parts.size() == 2) {
    const std::string &unit = parts[0];
    value = parts[1];
    if (unit == "s") {
      scale = 1000000000;
    } else if (unit == "ms") {
      scale = 1000000;
    } else if (unit == "us") {
      scale = 1000;
    } else if (unit == "ns") {
      scale = 1;
    } else {
      return make_error<ParseError>(this, str, "invalid interval unit");
    }
  } else {
    return make_error<ParseError>(this, str, "invalid interval format");
  }

  // Parse the integer part.
  auto res = util::to_uint(value);
  if (!res) {
    return make_error<ParseError>(this, str, "invalid interval value");
  }

  // Check for overflow when converting.
  if (*res > UINT64_MAX / scale) {
    return make_error<ParseError>(this, str, "overflow in interval value");
  }

  return make_list<IntervalAttachPoint>(*res * scale);
}

Result<AttachedProbeList> IntervalProvider::attach_single(
    std::unique_ptr<AttachPoint> &&attach_point,
    const BpfProgram &prog,
    [[maybe_unused]] std::optional<int> pid) const
{
  // Create perf event for timer-based triggering.
  struct perf_event_attr attr = {};
  attr.type = PERF_TYPE_SOFTWARE;
  attr.size = sizeof(struct perf_event_attr);
  attr.config = PERF_COUNT_SW_CPU_CLOCK;
  attr.sample_period =
      static_cast<IntervalAttachPoint &>(*attach_point).interval;
  attr.freq = 0; // Use period, not frequency

  // Open perf event on CPU 0 for all processes. In the future, this attachpoint
  // could support additional flags that are parsed to select different CPUs,
  // etc. For now, we always bind to CPU zero.
  int perf_event_fd = syscall(__NR_perf_event_open,
                              &attr,
                              -1, // pid (-1 means all processes)
                              0,  // cpu (0 means CPU 0)
                              -1, // group_fd
                              PERF_FLAG_FD_CLOEXEC);
  if (perf_event_fd < 0) {
    return make_error<SystemError>(
        "failed to open perf event for interval probe");
  }

  // Attach BPF program to perf event.
  auto *link = bpf_program__attach_perf_event(prog.bpf_prog(), perf_event_fd);
  if (!link) {
    close(perf_event_fd);
    return make_error<SystemError>(
        "failed to attach BPF program to perf event");
  }

  // Return AttachedProbe with the link & perf event descriptors.
  return make_list<IntervalAttachedProbe>(link,
                                          wrap_list(std::move(attach_point)),
                                          perf_event_fd);
}

} // namespace bpftrace::providers

CEREAL_REGISTER_TYPE(bpftrace::providers::IntervalAttachPoint)
CEREAL_REGISTER_POLYMORPHIC_RELATION(bpftrace::providers::AttachPoint,
                                     bpftrace::providers::IntervalAttachPoint)
