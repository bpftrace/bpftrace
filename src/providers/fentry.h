#pragma once

#include "providers/provider.h"

namespace bpftrace::providers {

enum class FentryType { fentry, fexit };

/// Provider for fentry attach points.
class FentryProviderBase : virtual public Provider {
public:
  FentryProviderBase(FentryType fentry_type) : fentry_type_(fentry_type) {};

  Result<AttachPointList> parse(
      const std::string &str,
       BtfLookup &btf,
      std::optional<int> pid = std::nullopt) const override;

  Result<AttachedProbeList> attach_single(
      std::unique_ptr<AttachPoint> &&attach_point,
      const BpfProgram &prog,
      std::optional<int> pid = std::nullopt) const override;

private:
  FentryType fentry_type_;
};

class FentryProvider : public ProviderImpl<FentryProvider, "fentry">,
                       public FentryProviderBase {
public:
  FentryProvider() : FentryProviderBase(FentryType::fentry) {};
};

class FexitProvider : public ProviderImpl<FexitProvider, "fexit">,
                      public FentryProviderBase {
public:
  FexitProvider() : FentryProviderBase(FentryType::fexit) {};
};

} // namespace bpftrace::providers
