#pragma once

#include "providers/provider.h"

namespace bpftrace::providers {

/// Provider for watchpoint attach points.
class WatchpointProvider
    : public ProviderImpl<WatchpointProvider, "watchpoint", "watch", "wp"> {
public:
  Result<AttachPointList> parse(
      const std::string &str,
      BtfLookup &btf,
      std::optional<int> pid = std::nullopt) const override;

  Result<AttachedProbeList> attach_single(
      std::unique_ptr<AttachPoint> &&attach_point,
      const BpfProgram &prog,
      std::optional<int> pid = std::nullopt) const override;
};

} // namespace bpftrace::providers
