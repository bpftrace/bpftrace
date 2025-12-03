#include <bpf/libbpf.h>

#include "bpfprogram.h"
#include "providers/rawtracepoint.h"

namespace bpftrace::providers {

Result<AttachPointList> RawTracepointProvider::parse(
    const std::string &str,
    [[maybe_unused]] BtfLookup &btf,
    [[maybe_unused]] std::optional<int> pid) const
{
  return make_list<SimpleAttachPoint>(str);
}

Result<AttachedProbeList> RawTracepointProvider::attach_single(
    std::unique_ptr<AttachPoint> &&attach_point,
    const BpfProgram &prog,
    [[maybe_unused]] std::optional<int> pid) const
{
  auto *link = bpf_program__attach_raw_tracepoint(prog.bpf_prog(),
                                                  attach_point->name().c_str());
  if (!link) {
    return make_error<AttachError>(this,
                                   std::move(attach_point),
                                   "failed to attach rawtracepoint");
  }

  return make_list<AttachedProbe>(link, wrap_list(std::move(attach_point)));
}

} // namespace bpftrace::providers
