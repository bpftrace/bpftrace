#include "providers/iter.h"
#include "bpfprogram.h"
#include "util/strings.h"
#include "util/wildcard.h"

namespace bpftrace::providers {

class IterAttachPoint : public AttachPoint {
public:
  IterAttachPoint(std::string iter_name) : iter_name(std::move(iter_name)) {};

  std::string name() const override
  {
    return iter_name;
  }

  bpf_prog_type prog_type() const override
  {
    return BPF_PROG_TYPE_TRACING;
  }

  bool can_multi_attach() const override
  {
    return false;
  }

  template <class Archive>
  void serialize([[maybe_unused]] Archive &ar)
  {
    ar(iter_name);
  }

  std::string iter_name;
};

static Result<std::set<std::string>> available_iters(BtfLookup &btf)
{
  auto btf_data = btf.get_kernel_btf();
  if (!btf_data) {
    return btf_data.takeError();
  }

  // Cache the available iters in a static set.
  static std::set<std::string> iters;
  if (!iters.empty()) {
    return iters;
  }

  for (const auto &type : *btf_data) {
    if (type.is<btf::Function>()) {
      auto func = type.as<btf::Function>();
      std::string func_name = func.name();

      // Check if this is a bpf_iter__ function.
      if (func_name.starts_with("bpf_iter__")) {
        // Extract the iter name from "bpf_iter__<name>"
        std::string iter_name = func_name.substr(10); // Remove "bpf_iter__".
        if (!iter_name.empty()) {
          iters.emplace(iter_name);
        }
      }
    }
  }

  return iters;
}

Result<std::vector<std::unique_ptr<AttachPoint>>> IterProvider::parse(
    const std::string &str,
    BtfLookup &btf,
    [[maybe_unused]] std::optional<int> pid) const
{
  AttachPointList results;

  auto all_iters = available_iters(btf);
  if (!all_iters) {
    return all_iters.takeError();
  }

  bool start_wildcard, end_wildcard;
  auto tokens = util::get_wildcard_tokens(str, start_wildcard, end_wildcard);
  for (const auto &iter_name : *all_iters) {
    if (util::wildcard_match(iter_name, tokens, start_wildcard, end_wildcard)) {
      results.emplace_back(std::make_unique<IterAttachPoint>(iter_name));
    }
  }
  if (util::has_wildcard(str) && results.empty()) {
    return make_error<ParseError>(this, str, "iter function not found");
  }
  return results;
}

Result<AttachedProbeList> IterProvider::attach_single(
    std::unique_ptr<AttachPoint> &&attach_point,
    const BpfProgram &prog,
    [[maybe_unused]] std::optional<int> pid) const
{
  auto *link = bpf_program__attach_iter(prog.bpf_prog(), nullptr);
  if (!link) {
    return make_error<AttachError>(this,
                                   std::move(attach_point),
                                   "failed to attach iter");
  }

  return make_list<AttachedProbe>(link, wrap_list(std::move(attach_point)));
}

} // namespace bpftrace::providers
