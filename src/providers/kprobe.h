#pragma once

#include "providers/provider.h"

namespace bpftrace::providers {

enum class KprobeType { kprobe, kretprobe, ksession };

/// Provider for kprobe, kretprobe, and ksession attach points.
class KprobeProviderBase : virtual public Provider {
public:
  KprobeProviderBase(KprobeType type) : kprobe_type_(type) {};

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
  KprobeType kprobe_type_;
};

class KprobeProvider : public ProviderImpl<KprobeProvider, "kprobe", "k">,
                       public KprobeProviderBase {
public:
  KprobeProvider() : KprobeProviderBase(KprobeType::kprobe) {};
};

class KretprobeProvider
    : public ProviderImpl<KretprobeProvider, "kretprobe", "kr">,
      public KprobeProviderBase {
public:
  KretprobeProvider() : KprobeProviderBase(KprobeType::kretprobe) {};
};

class KsessionProvider
    : public ProviderImpl<KsessionProvider, "ksession", "ks">,
      public KprobeProviderBase {
public:
  KsessionProvider() : KprobeProviderBase(KprobeType::ksession) {};
};

} // namespace bpftrace::providers
