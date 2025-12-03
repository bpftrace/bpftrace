#include "providers/kprobe.h"
#include "bpfprogram.h"
#include "util/int_parser.h"
#include "util/strings.h"
#include "util/wildcard.h"

namespace bpftrace::providers {

class KprobeAttachPoint : public AttachPoint {
public:
  KprobeAttachPoint(std::string target, std::string func, uint64_t func_offset)
      : target(std::move(target)),
        func(std::move(func)),
        func_offset(func_offset)
  {
  }

  std::string name() const override
  {
    std::string result;
    if (!target.empty() && target != "vmlinux") {
      result += target + ":";
    }
    result += func;
    if (func_offset != 0) {
      result += "+" + std::to_string(func_offset);
    }
    return result;
  }

  bpf_prog_type prog_type() const override
  {
    return BPF_PROG_TYPE_KPROBE;
  }

  bool can_multi_attach() const override
  {
    return func_offset == 0 && (target.empty() || target == "vmlinux");
  }

  template <class Archive>
  void serialize([[maybe_unused]] Archive &ar)
  {
    ar(target, func, func_offset);
  }

  std::string target;
  std::string func;
  uint64_t func_offset;
};

Result<AttachPointList> KprobeProviderBase::parse(
    const std::string &str,
    BtfLookup &btf,
    [[maybe_unused]] std::optional<int> pid) const
{
  AttachPointList results;

  auto parts = util::split_string(str, ':');
  if (parts.size() > 2) {
    return make_error<ParseError>(this, str, "invalid kprobe format");
  }

  std::string target = "vmlinux";
  std::string func = parts.back();
  uint64_t func_offset = 0;
  if (parts.size() == 2) {
    target = parts[0];
  }

  // Handle function+offset syntax.
  auto plus_pos = func.find('+');
  if (plus_pos != std::string::npos) {
    if (kprobe_type_ == KprobeType::kretprobe) {
      return make_error<ParseError>(this, str, "kretprobes cannot use offsets");
    }
    if (kprobe_type_ == KprobeType::ksession) {
      return make_error<ParseError>(this,
                                    str,
                                    "ksession probes cannot use offsets");
    }

    std::string func_name = func.substr(0, plus_pos);
    std::string offset_str = func.substr(plus_pos + 1);

    auto offset_result = util::to_uint(offset_str);
    if (!offset_result) {
      return make_error<ParseError>(this, str, "invalid offset: " + offset_str);
    }
    func_offset = *offset_result;
    func = func_name;
  }

  // Get available modules to search.
  std::vector<std::string> modules_to_search;
  if (target.empty() || target == "vmlinux") {
    modules_to_search.emplace_back("vmlinux");
  } else if (util::has_wildcard(target)) {
    auto modules = btf.list_modules();
    if (!modules) {
      return modules.takeError();
    }

    bool start_wildcard, end_wildcard;
    auto tokens = util::get_wildcard_tokens(target,
                                            start_wildcard,
                                            end_wildcard);

    for (const auto &module : *modules) {
      if (util::wildcard_match(module, tokens, start_wildcard, end_wildcard)) {
        modules_to_search.push_back(module);
      }
    }
  } else {
    modules_to_search.push_back(target);
  }

  // Search for functions in each module.
  for (const auto &module : modules_to_search) {
    auto btf_types = btf.get_kernel_btf(module);
    if (!btf_types) {
      return btf_types.takeError();
    }

    if (util::has_wildcard(func)) {
      bool start_wildcard, end_wildcard;
      auto tokens = util::get_wildcard_tokens(func,
                                              start_wildcard,
                                              end_wildcard);

      for (const auto &type : *btf_types) {
        if (type.is<btf::Function>()) {
          auto btf_func = type.as<btf::Function>();
          std::string func_name = btf_func.name();

          if (util::wildcard_match(
                  func_name, tokens, start_wildcard, end_wildcard)) {
            results.emplace_back(std::make_unique<KprobeAttachPoint>(
                module, func_name, func_offset));
          }
        }
      }
    } else {
      // Attempt to find the specific function name.
      auto btf_func = btf_types->lookup<btf::Function>(func);
      if (btf_func) {
        results.emplace_back(
            std::make_unique<KprobeAttachPoint>(module, func, func_offset));
      }
    }
  }

  // If we had no wildcards, ensure something was found.
  if (!util::has_wildcard(func) && results.empty()) {
    return make_error<ParseError>(this, func, "function not found");
  }

  return results;
}

Result<AttachedProbeList> KprobeProviderBase::attach_single(
    std::unique_ptr<AttachPoint> &&attach_point,
    const BpfProgram &prog,
    [[maybe_unused]] std::optional<int> pid) const
{
  if (kprobe_type_ == KprobeType::ksession) {
    return make_error<AttachError>(this,
                                   std::move(attach_point),
                                   "ksession probes require multi-attach mode");
  }

  // Use the old fashion single-attach API for regular kprobe/kretprobe.
  auto &kprobe_attach_point = attach_point->as<KprobeAttachPoint>();

  struct bpf_kprobe_opts opts = {};
  opts.sz = sizeof(opts);
  opts.offset = kprobe_attach_point.func_offset;
  opts.retprobe = kprobe_type_ == KprobeType::kretprobe;

  auto *link = bpf_program__attach_kprobe_opts(prog.bpf_prog(),
                                               kprobe_attach_point.func.c_str(),
                                               &opts);
  if (!link) {
    return make_error<AttachError>(this,
                                   std::move(attach_point),
                                   "failed to attach kprobe");
  }

  return make_list<AttachedProbe>(link, wrap_list(std::move(attach_point)));
}

Result<AttachedProbeList> KprobeProviderBase::attach_multi(
    AttachPointList &&attach_points,
    const BpfProgram &prog,
    [[maybe_unused]] std::optional<int> pid) const
{
  if (attach_points.empty()) {
    return AttachedProbeList{};
  }

  // Collect function names for multi-attach.
  std::vector<const char *> syms;
  std::vector<std::string> func_names;
  for (auto &attach_point : attach_points) {
    auto &kprobe_attach_point = attach_point->as<KprobeAttachPoint>();
    func_names.push_back(kprobe_attach_point.func);
    syms.push_back(func_names.back().c_str());
  }

  if (kprobe_type_ == KprobeType::ksession) {
    struct bpf_link_create_opts opts = {};
    opts.sz = sizeof(opts);
    opts.kprobe_multi.syms = syms.data();
    opts.kprobe_multi.cnt = syms.size();
    opts.kprobe_multi.flags = 0;

    int link_fd = bpf_link_create(
        prog.fd(), 0, BPF_TRACE_KPROBE_SESSION, &opts);
    if (link_fd < 0) {
      return make_error<AttachError>(this,
                                     std::move(attach_points[0]),
                                     "failed to attach ksession probe");
    }

    // Return a list with the link_fd bound directly.
    return make_list<AttachedProbe>(link_fd, std::move(attach_points));
  } else {
    // Regular kprobe/kretprobe multi-attach
    struct bpf_kprobe_multi_opts opts = {};
    opts.sz = sizeof(opts);
    opts.syms = syms.data();
    opts.cnt = syms.size();
    opts.retprobe = kprobe_type_ == KprobeType::kretprobe;

    auto *link = bpf_program__attach_kprobe_multi_opts(prog.bpf_prog(),
                                                       nullptr,
                                                       &opts);
    if (!link) {
      return make_error<AttachError>(this,
                                     std::move(attach_points[0]),
                                     "failed to attach multi kprobe");
    }

    return make_list<AttachedProbe>(link, std::move(attach_points));
  }
}

} // namespace bpftrace::providers

CEREAL_REGISTER_TYPE(bpftrace::providers::KprobeAttachPoint)
CEREAL_REGISTER_POLYMORPHIC_RELATION(bpftrace::providers::AttachPoint,
                                     bpftrace::providers::KprobeAttachPoint)
