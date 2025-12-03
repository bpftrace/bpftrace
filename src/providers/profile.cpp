#include <bpf/libbpf.h>
#include <cereal/types/variant.hpp>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <variant>

#include "bpfprogram.h"
#include "providers/profile.h"
#include "util/int_parser.h"
#include "util/strings.h"

namespace bpftrace::providers {

struct FrequencySpec {
  uint64_t hz;

  template <class Archive>
  void serialize([[maybe_unused]] Archive &ar)
  {
    ar(hz);
  }
};

struct PeriodSpec {
  uint64_t nanoseconds;

  template <class Archive>
  void serialize([[maybe_unused]] Archive &ar)
  {
    ar(nanoseconds);
  }
};

class ProfileAttachPoint : public AttachPoint {
public:
  ProfileAttachPoint(std::variant<FrequencySpec, PeriodSpec> spec)
      : spec(spec) {};

  std::string name() const override
  {
    if (std::holds_alternative<FrequencySpec>(spec)) {
      return "hz:" + std::to_string(std::get<FrequencySpec>(spec).hz);
    } else {
      auto ns = std::get<PeriodSpec>(spec).nanoseconds;
      if (ns > 1000000000 && ns % 1000000000 == 0) {
        return "s:" + std::to_string(ns / 1000000000);
      } else if (ns > 1000000 && ns % 1000000 == 0) {
        return "ms:" + std::to_string(ns / 1000000);
      } else if (ns > 1000 && ns % 1000 == 0) {
        return "us:" + std::to_string(ns / 1000);
      } else {
        return "ns:" + std::to_string(ns);
      }
    }
  }

  template <class Archive>
  void serialize([[maybe_unused]] Archive &ar)
  {
    ar(spec);
  }

  std::variant<FrequencySpec, PeriodSpec> spec;
};

class ProfileAttachedProbe : public AttachedProbe {
public:
  ProfileAttachedProbe(struct bpf_link *link,
                       AttachPointList &&attach_points,
                       int perf_event_fd)
      : AttachedProbe(link, std::move(attach_points)),
        perf_event_fd_(perf_event_fd) {};

private:
  util::FD perf_event_fd_;
};

Result<AttachPointList> ProfileProvider::parse(
    const std::string &str,
    [[maybe_unused]] BtfLookup &btf,
    [[maybe_unused]] std::optional<int> pid) const
{
  auto parts = util::split_string(str, ':');
  if (parts.size() != 2) {
    return make_error<ParseError>(this, str, "invalid profile format");
  }

  const std::string &unit = parts[0];
  const std::string &rate_str = parts[1];
  auto res = util::to_uint(rate_str);
  if (!res) {
    return make_error<ParseError>(this, str, "invalid rate value");
  }

  std::variant<FrequencySpec, PeriodSpec> spec;
  if (unit == "hz") {
    spec = FrequencySpec{ *res };
  } else if (unit == "s") {
    spec = PeriodSpec{ *res * 1000000000 };
  } else if (unit == "ms") {
    spec = PeriodSpec{ *res * 1000000 };
  } else if (unit == "us") {
    spec = PeriodSpec{ *res * 1000 };
  } else if (unit == "ns") {
    spec = PeriodSpec{ *res };
  } else {
    return make_error<ParseError>(this, str, "invalid unit");
  }

  return make_list<ProfileAttachPoint>(spec);
}

Result<AttachedProbeList> ProfileProvider::attach_single(
    std::unique_ptr<AttachPoint> &&attach_point,
    const BpfProgram &prog,
    std::optional<int> pid) const
{
  struct perf_event_attr attr = {};
  attr.type = PERF_TYPE_SOFTWARE;
  attr.size = sizeof(struct perf_event_attr);
  attr.config = PERF_COUNT_SW_CPU_CLOCK;

  std::visit(
      [&attr](const auto &spec) {
        using T = std::decay_t<decltype(spec)>;
        if constexpr (std::is_same_v<T, FrequencySpec>) {
          attr.sample_freq = spec.hz;
          attr.freq = 1;
        } else if constexpr (std::is_same_v<T, PeriodSpec>) {
          attr.sample_period = spec.nanoseconds;
          attr.freq = 0;
        }
      },
      static_cast<ProfileAttachPoint &>(*attach_point).spec);

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
    return make_error<SystemError>(
        "failed to open perf event for profile probe");
  }

  auto *link = bpf_program__attach_perf_event(prog.bpf_prog(), perf_event_fd);
  if (!link) {
    close(perf_event_fd);
    return make_error<SystemError>("failed to attach perf event");
  }

  return make_list<ProfileAttachedProbe>(link,
                                         wrap_list(std::move(attach_point)),
                                         perf_event_fd);
}

} // namespace bpftrace::providers

CEREAL_REGISTER_TYPE(bpftrace::providers::ProfileAttachPoint)
CEREAL_REGISTER_POLYMORPHIC_RELATION(bpftrace::providers::AttachPoint,
                                     bpftrace::providers::ProfileAttachPoint)
