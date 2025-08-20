#pragma once

#include "providers/provider.h"

namespace bpftrace::providers {

// Common base for special providers.
class SpecialProviderBase : virtual public Provider {
public:
  SpecialProviderBase(AttachPoint::Action action) : action_(action) {};

  Result<AttachPointList> parse(
      const std::string &str,
       BtfLookup &btf,
      std::optional<int> pid = std::nullopt) const override;

  AttachPoint::Action action()
  {
    return action_;
  }

  Result<> run_single(std::unique_ptr<AttachPoint> &attach_point,
                      const BpfProgram &prog) const override;

private:
  AttachPoint::Action action_;
};

// Provider for begin probes.
class BeginProvider : public SpecialProviderBase,
                      public ProviderImpl<BeginProvider, "begin"> {
public:
  BeginProvider() : SpecialProviderBase(AttachPoint::Action::Pre) {};
};

// Provider for end probes.
class EndProvider : public SpecialProviderBase,
                    public ProviderImpl<EndProvider, "end"> {
public:
  EndProvider() : SpecialProviderBase(AttachPoint::Action::Post) {};
};

// Provider for self probes.
class SelfProvider : public SpecialProviderBase,
                     public ProviderImpl<SelfProvider, "self"> {
public:
  SelfProvider() : SpecialProviderBase(AttachPoint::Action::Manual) {};

  Result<AttachPointList> parse(
      const std::string &str,
       BtfLookup &btf,
      std::optional<int> pid = std::nullopt) const override;
};

} // namespace bpftrace::providers
