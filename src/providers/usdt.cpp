#include <bpf/libbpf.h>
#include <utility>

#include "bpfprogram.h"
#include "providers/usdt.h"
#include "util/strings.h"

namespace bpftrace::providers {

class UsdtAttachPoint : public AttachPoint {
public:
  UsdtAttachPoint() = default;
  UsdtAttachPoint(std::string target,
                  std::string provider_name,
                  std::string probe_name)
      : target(std::move(target)),
        provider_name(std::move(provider_name)),
        probe_name(std::move(probe_name)) {};

  std::string name() const override
  {
    if (provider_name.empty()) {
      return target + ":" + probe_name;
    } else {
      return target + ":" + provider_name + ":" + probe_name;
    }
  }

  bpf_prog_type prog_type() const override
  {
    return BPF_PROG_TYPE_KPROBE;
  }

  template <class Archive>
  void serialize([[maybe_unused]] Archive &ar)
  {
    ar(target, provider_name, probe_name);
  }

  std::string target;
  std::string provider_name;
  std::string probe_name;
};

Result<AttachPointList> UsdtProvider::parse(
    const std::string &str,
    [[maybe_unused]] BtfLookup &btf,
    [[maybe_unused]] std::optional<int> pid) const
{
  auto parts = util::split_string(str, ':');
  if (parts.size() != 2 && parts.size() != 3) {
    return make_error<ParseError>(this, str, "invalid usdt format");
  }

  std::string target, provider_name, probe_name;
  if (parts.size() == 2) {
    target = parts[0];
    provider_name = "";
    probe_name = parts[1];
  } else {
    target = parts[0];
    provider_name = parts[1];
    probe_name = parts[2];
  }

  return make_list<UsdtAttachPoint>(target, provider_name, probe_name);
}

Result<AttachedProbeList> UsdtProvider::attach_single(
    std::unique_ptr<AttachPoint> &&attach_point,
    const BpfProgram &prog,
    std::optional<int> pid) const
{
  const auto &usdt_attach_point = attach_point->as<UsdtAttachPoint>();
  auto *link = bpf_program__attach_usdt(
      prog.bpf_prog(),
      pid.value_or(-1),
      usdt_attach_point.target.c_str(),
      usdt_attach_point.provider_name.empty()
          ? nullptr
          : usdt_attach_point.provider_name.c_str(),
      usdt_attach_point.probe_name.c_str(),
      nullptr);

  if (!link) {
    return make_error<SystemError>("failed to attach USDT probe");
  }

  return make_list<AttachedProbe>(link, wrap_list(std::move(attach_point)));
}

} // namespace bpftrace::providers

CEREAL_REGISTER_TYPE(bpftrace::providers::UsdtAttachPoint)
CEREAL_REGISTER_POLYMORPHIC_RELATION(bpftrace::providers::AttachPoint,
                                     bpftrace::providers::UsdtAttachPoint)
