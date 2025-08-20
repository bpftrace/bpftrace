#include "providers/fentry.h"
#include "bpfprogram.h"
#include "util/bpf_progs.h"
#include "util/int_parser.h"
#include "util/strings.h"
#include "util/wildcard.h"

namespace bpftrace::providers {

class FentryAttachPoint : public AttachPoint {
public:
  FentryAttachPoint(std::string target, std::string func, FentryType type)
      : target(std::move(target)), func(std::move(func)), type(type) {};

  std::string name() const override
  {
    if (!target.empty() && target != "vmlinux") {
      return target + ":" + func;
    } else {
      return func;
    }
  }

  Result<btf::AnyType> context_type(
      [[maybe_unused]] const btf::Types &kernel_types) const override
  {
    if (type == FentryType::fentry) {
      // Return a construct structure that has arguments that match the BTF
      // definition in the kernel. This is pulled from the kernel_types.
    } else {
      // Return a type that matches just the return value.
    }
    return make_error<SystemError>("no context type", ENOENT);
  }

  std::string target;
  std::string func;
  FentryType type;
};

Result<AttachPointList> FentryProviderBase::parse(
    const std::string &str,
    BtfLookup &btf,
    [[maybe_unused]] std::optional<int> pid) const
{
  auto parts = util::split_string(str, ':');
  if (parts.size() > 2) {
    return make_error<ParseError>(this, str, "invalid fentry format");
  }

  std::string target = "vmlinux";
  const std::string &func = parts.back();
  if (parts.size() == 2) {
    target = parts[0];
  }

  // We can't load types for all targets.
  if (util::has_wildcard(target)) {
    return make_error<ParseError>(this,
                                  str,
                                  "wildcards not supported for target");
  }

  AttachPointList results;
  if (target == "bpf") {
    auto bpf_progs = util::get_bpf_progs();
    if (util::has_wildcard(func)) {
      // Get all running BPF programs and filter by pattern.
      bool start_wildcard, end_wildcard;
      auto tokens = util::get_wildcard_tokens(func,
                                              start_wildcard,
                                              end_wildcard);

      for (const auto &[id, symbol] : bpf_progs) {
        std::string full_symbol = std::to_string(id) + ":" + symbol;

        // Try matching against just the symbol name or the full "id:symbol".
        if (util::wildcard_match(
                symbol, tokens, start_wildcard, end_wildcard) ||
            util::wildcard_match(
                full_symbol, tokens, start_wildcard, end_wildcard)) {
          auto attach_point = std::make_unique<FentryAttachPoint>("bpf",
                                                                  full_symbol,
                                                                  fentry_type_);
          results.emplace_back(std::move(attach_point));
        }
      }
    } else {
      // Try to parse as program ID.
      auto prog_id = util::to_uint(func);
      if (prog_id) {
        for (const auto &[id, symbol] : bpf_progs) {
          if (id == *prog_id) {
            auto attach_point = std::make_unique<FentryAttachPoint>(
                "bpf", std::to_string(id) + ":" + symbol, fentry_type_);
            attach_point->type = fentry_type_;
            results.emplace_back(std::move(attach_point));
            break;
          }
        }
      } else {
        // Not a program ID, try to find by symbol
        // name.
        for (const auto &[id, symbol] : bpf_progs) {
          if (symbol == func) {
            auto attach_point = std::make_unique<FentryAttachPoint>(
                "bpf", std::to_string(id) + ":" + symbol, fentry_type_);
            attach_point->type = fentry_type_;
            results.emplace_back(std::move(attach_point));
          }
        }
      }
    }
  } else {
    auto modules = btf.list_modules();
    if (!modules) {
      return modules.takeError();
    }
    bool start_wildcard_module, end_wildcard_module;
    auto tokens_module = util::get_wildcard_tokens(target,
                                                   start_wildcard_module,
                                                   end_wildcard_module);

    for (const auto &module : *modules) {
      // Skip as this is not relevant.
      if (!util::wildcard_match(module,
                                tokens_module,
                                start_wildcard_module,
                                end_wildcard_module)) {
        continue;
      }
      // Load the relevant kernel types.
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
              auto attach_point = std::make_unique<FentryAttachPoint>(
                  target, func_name, fentry_type_);
              results.emplace_back(std::move(attach_point));
            }
          }
        }
      } else {
        auto btf_func = btf_types->lookup<btf::Function>(func);
        if (!btf_func) {
          return make_error<ParseError>(this, str, "function not found in btf");
        }
        auto attach_point = std::make_unique<FentryAttachPoint>(
            target, btf_func->name(), fentry_type_);
        results.emplace_back(std::move(attach_point));
      }
    }
  }
  if (!util::has_wildcard(str) && results.empty()) {
    return make_error<ParseError>(this, str, "function not found");
  }

  return results;
}

Result<AttachedProbeList> FentryProviderBase::attach_single(
    std::unique_ptr<AttachPoint> &&attach_point,
    const BpfProgram &prog,
    [[maybe_unused]] std::optional<int> pid) const
{
  // Use libbpf to attach the fentry/fexit to the target kernel function.
  struct bpf_link *link = bpf_program__attach_trace(prog.bpf_prog());

  if (!link) {
    return make_error<AttachError>(this,
                                   std::move(attach_point),
                                   fentry_type_ == FentryType::fentry
                                       ? "failed to attach fentry to function"
                                       : "failed to attach fexit to function");
  }

  return make_list<AttachedProbe>(link, wrap_list(std::move(attach_point)));
}

} // namespace bpftrace::providers
