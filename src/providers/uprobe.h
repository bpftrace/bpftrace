#pragma once

#include "providers/provider.h"

namespace bpftrace::providers {

enum class UprobeType { uprobe, uretprobe };

/// Provider for uprobe and uretprobe attach points.
class UprobeProviderBase : virtual public Provider {
public:
  UprobeProviderBase(UprobeType uprobe_type) : uprobe_type_(uprobe_type) {};

  Result<AttachPointList> parse(
      const std::string &str,
       BtfLookup &btf,
      std::optional<int> pid = std::nullopt) const override;

  Result<AttachedProbeList> attach_single(
      std::unique_ptr<AttachPoint> &&attach_point,
      const BpfProgram &prog,
      std::optional<int> pid = std::nullopt) const override;

  Result<AttachedProbeList> attach_multi(
      AttachPointList &&attach_points,
      const BpfProgram &prog,
      std::optional<int> pid = std::nullopt) const override;

private:
  UprobeType uprobe_type_;
};

class UprobeProvider : public ProviderImpl<UprobeProvider, "uprobe", "u">,
                       public UprobeProviderBase {
public:
  UprobeProvider() : UprobeProviderBase(UprobeType::uprobe) {};
};

class UretprobeProvider
    : public ProviderImpl<UprobeProvider, "uretprobe", "ur">,
      public UprobeProviderBase {
public:
  UretprobeProvider() : UprobeProviderBase(UprobeType::uretprobe) {};
};

} // namespace bpftrace::providers
