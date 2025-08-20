#pragma once

#include "providers/provider.h"

namespace bpftrace::providers {

/// Provider for software & hardware event attach points.
class PerfProvider : public ProviderImpl<PerfProvider,
                                         "perf",
                                         "hardware",
                                         "software",
                                         "hw",
                                         "sw"> {
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
