#include <utility>

#include "bpfprogram.h"
#include "providers/watchpoint.h"
#include "util/strings.h"

namespace bpftrace::providers {

class WatchpointAttachPoint : public AttachPoint {
public:
  WatchpointAttachPoint(std::string address, size_t len, std::string mode)
      : address(std::move(address)), len(len), mode(std::move(mode)) {};

  std::string name() const override
  {
    return address + ":" + std::to_string(len) + ":" + mode;
  }

  template <class Archive>
  void serialize([[maybe_unused]] Archive &ar)
  {
    ar(address, len, mode);
  }

  std::string address;
  size_t len;
  std::string mode;
};

Result<AttachPointList> WatchpointProvider::parse(
    const std::string &str,
    [[maybe_unused]] BtfLookup &btf,
    [[maybe_unused]] std::optional<int> pid) const
{
  auto parts = util::split_string(str, ':');
  if (parts.size() < 2 || parts.size() > 4) {
    return make_error<ParseError>(this, str, "invalid watchpoint format");
  }

  std::string address = parts[1];
  size_t len = 8;          // default length
  std::string mode = "rw"; // default mode

  if (parts.size() >= 3) {
    try {
      len = std::stoull(parts[2]);
    } catch (const std::exception &) {
      return make_error<ParseError>(this, str, "invalid length: " + parts[2]);
    }
  }

  if (parts.size() == 4) {
    mode = parts[3];
    if (mode != "r" && mode != "w" && mode != "rw") {
      return make_error<ParseError>(this, str, "invalid mode: " + mode);
    }
  }

  return make_list<WatchpointAttachPoint>(address, len, mode);
}

Result<AttachedProbeList> WatchpointProvider::attach_single(
    std::unique_ptr<AttachPoint> &&attach_point,
    [[maybe_unused]] const BpfProgram &prog,
    [[maybe_unused]] std::optional<int> pid) const
{
  return make_error<AttachError>(this,
                                 std::move(attach_point),
                                 "watchpoint attach not yet implemented");
}

} // namespace bpftrace::providers

CEREAL_REGISTER_TYPE(bpftrace::providers::WatchpointAttachPoint)
CEREAL_REGISTER_POLYMORPHIC_RELATION(bpftrace::providers::AttachPoint,
                                     bpftrace::providers::WatchpointAttachPoint)
