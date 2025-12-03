#include <bpf/libbpf.h>

#include "btf/btf.h"
#include "log.h"
#include "providers/provider.h"

namespace bpftrace::providers {

std::ostream &operator<<(std::ostream &out, const AttachPoint &attach_point)
{
  out << attach_point.name();
  return out;
}

char AttachError::ID = 0;

void AttachError::log(llvm::raw_ostream &OS) const
{
  std::stringstream ss;
  ss << "attach error for " << provider_->name() << ":" << attach_point_->name()
     << ": " << err_;
  OS << ss.str();
}

int AttachedProbe::link_fd() const
{
  if (std::holds_alternative<struct bpf_link *>(link_)) {
    return bpf_link__fd(std::get<struct bpf_link *>(link_));
  } else {
    return std::get<util::FD>(link_).get();
  }
}

AttachedProbe::~AttachedProbe()
{
  if (std::holds_alternative<struct bpf_link *>(link_)) {
    if (bpf_link__destroy(std::get<struct bpf_link *>(link_))) {
      LOG(WARNING) << "failed to destroy bpf_link: " << strerror(errno);
    }
  }
}

char ParseError::ID = 0;

void ParseError::log(llvm::raw_ostream &OS) const
{
  OS << "parse error for provider " << provider_->name() << " given target "
     << target_ << ": " << err_;
}

char ProviderConflict::ID = 0;

void ProviderConflict::log(llvm::raw_ostream &OS) const
{
  OS << "provider name conflict: " << first_->name()
     << " is already registered; ";
  if (!first_->aliases().empty()) {
    OS << "original has aliases: ";
    for (const auto &alias : first_->aliases()) {
      OS << alias << ", ";
    }
  } else {
    OS << "original has no aliases, ";
  }
  if (!second_->aliases().empty()) {
    OS << "other provider has aliases: ";
    for (const auto &alias : second_->aliases()) {
      OS << alias << ", ";
    }
  } else {
    OS << "other provider has no aliases, ";
  }
  OS << "unable to proceed";
}

Result<bpftrace::btf::AnyType> AttachPoint::context_type(
    const btf::Types &kernel_types) const
{
  return kernel_types.lookup<btf::Void>(0);
}

Result<bpftrace::btf::AnyType> AttachPoint::return_type(
    const btf::Types &kernel_types) const
{
  return kernel_types.lookup<btf::Void>(0);
}

Result<> Provider::run(std::unique_ptr<AttachPoint> &attach_point,
                       const BpfProgram &prog) const
{
  return run_single(attach_point, prog);
}

Result<> Provider::run_single(
    [[maybe_unused]] std::unique_ptr<AttachPoint> &attach_point,
    [[maybe_unused]] const BpfProgram &prog) const
{
  return make_error<SystemError>("run not supported", EINVAL);
}

Result<AttachedProbeList> Provider::attach(AttachPointList &&attach_points,
                                           const BpfProgram &prog,
                                           std::optional<int> pid) const
{
  if (attach_points.empty()) {
    return AttachedProbeList();
  }

  // Validate all the providers & construct the attach strategy.
  AttachPointList multi_attachable;
  AttachPointList single_attachable;
  for (auto &attach_point : attach_points) {
    if (attach_point->can_multi_attach()) {
      multi_attachable.emplace_back(std::move(attach_point));
    } else {
      single_attachable.emplace_back(std::move(attach_point));
    }
  }

  // Attempt the multi-attach first.
  auto ok = attach_multi(std::move(multi_attachable), prog, pid);
  if (!ok) {
    return ok.takeError();
  }
  AttachedProbeList result = std::move(*ok);

  // Attach the single-attach instances.
  for (auto &attach_point : single_attachable) {
    auto ok = attach_single(std::move(attach_point), prog, pid);
    if (ok) {
      for (auto &val : *ok) {
        result.emplace_back(std::move(val));
      }
    } else {
      return ok.takeError();
    }
  }

  return result;
}

Result<AttachedProbeList> Provider::attach_single(
    [[maybe_unused]] std::unique_ptr<AttachPoint> &&attach_point,
    [[maybe_unused]] const BpfProgram &prog,
    [[maybe_unused]] std::optional<int> pid) const
{
  return make_error<SystemError>("single attach not supported");
}

Result<AttachedProbeList> Provider::attach_multi(
    [[maybe_unused]] AttachPointList &&attach_points,
    [[maybe_unused]] const BpfProgram &prog,
    [[maybe_unused]] std::optional<int> pid) const
{
  return make_error<SystemError>("multi attach not supported");
}

} // namespace bpftrace::providers

CEREAL_REGISTER_TYPE(bpftrace::providers::AttachPoint)
CEREAL_REGISTER_TYPE(bpftrace::providers::SimpleAttachPoint)
CEREAL_REGISTER_POLYMORPHIC_RELATION(bpftrace::providers::AttachPoint,
                                     bpftrace::providers::SimpleAttachPoint)
