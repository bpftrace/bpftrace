#pragma once

#include "providers/provider.h"

namespace bpftrace::providers {

/// Provider for benchmark probes.
class BenchmarkProvider : public ProviderImpl<BenchmarkProvider, "bench", "b"> {
public:
  Result<AttachPointList> parse(
      const std::string &str,
       BtfLookup &btf,
      std::optional<int> pid = std::nullopt) const override;

  Result<> run_single(std::unique_ptr<AttachPoint> &attach_point,
                      const BpfProgram &prog) const override;
};

} // namespace bpftrace::providers
