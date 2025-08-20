#include <blazesym.h>
#include <unordered_map>

#include "bpfprogram.h"
#include "cxxdemangler/cxxdemangler.h"
#include "providers/uprobe.h"
#include "scopeguard.h"
#include "util/int_parser.h"
#include "util/paths.h"
#include "util/strings.h"
#include "util/symbols.h"
#include "util/system.h"
#include "util/wildcard.h"

namespace bpftrace::providers {

class UprobeAttachPoint : public AttachPoint {
public:
  UprobeAttachPoint(std::string target,
                    std::string func,
                    uint64_t func_offset,
                    uint64_t address)
      : target(std::move(target)),
        func(std::move(func)),
        func_offset(func_offset),
        address(address) {};

  std::string name() const override
  {
    std::string result = target + ":" + func;
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
    return true;
  }

  template <class Archive>
  void serialize([[maybe_unused]] Archive &ar)
  {
    ar(target, func, func_offset, address);
  }

  std::string target;
  std::string func;
  uint64_t func_offset;
  uint64_t address;
};

// Helper function to get symbols using blazesym
static std::set<std::string> get_symbols_from_binary(
    const std::string &binary_path)
{
  std::set<std::string> symbols;

  auto *inspector = blaze_inspector_new();
  if (!inspector) {
    return symbols;
  }

  blaze_inspect_elf_src src = {
    .type_size = sizeof(src),
    .path = binary_path.c_str(),
    .debug_syms = true,
  };

  // Get all symbols.
  const auto *all_syms = blaze_inspect_syms_elf(inspector, &src, nullptr, 0);
  if (all_syms) {
    for (size_t i = 0; all_syms[i] != nullptr; ++i) {
      if (all_syms[i]->name) {
        symbols.insert(std::string(all_syms[i]->name));
      }
    }
    blaze_inspect_syms_free(all_syms);
  }

  blaze_inspector_free(inspector);
  return symbols;
}

static std::optional<uint64_t> resolve_symbol_blazesym(
    const std::string &target,
    const std::string &func,
    uint64_t func_offset)
{
  auto *inspector = blaze_inspector_new();
  if (!inspector) {
    return std::nullopt;
  }

  blaze_inspect_elf_src src = {
    .type_size = sizeof(src),
    .path = target.c_str(),
    .debug_syms = true,
  };

  const char *names[] = { func.c_str() };
  const auto *sym_infos = blaze_inspect_syms_elf(inspector, &src, names, 1);

  if (!sym_infos || !sym_infos[0]) {
    if (sym_infos) {
      blaze_inspect_syms_free(sym_infos);
    }
    blaze_inspector_free(inspector);
    return std::nullopt;
  }

  uint64_t addr = sym_infos[0]->addr;
  uint64_t offset = addr + func_offset;

  blaze_inspect_syms_free(sym_infos);
  blaze_inspector_free(inspector);

  return offset;
}

Result<AttachPointList> UprobeProviderBase::parse(
    const std::string &str,
    [[maybe_unused]] BtfLookup &btf,
    std::optional<int> pid) const
{
  auto parts = util::split_string(str, ':');
  if (parts.size() < 3 || parts.size() > 4) {
    return make_error<ParseError>(this, str, "invalid uprobe format");
  }

  std::string target = parts[1];
  std::string func = parts[2];
  std::string lang;
  bool enable_demangling = false;

  // Check for language specifier like "uprobe:target:cpp:func".
  if (parts.size() == 4) {
    lang = parts[2];
    func = parts[3];
    enable_demangling = (lang == "cpp" || lang == "cxx" || lang == "c++" ||
                         lang == "rust");
  }

  uint64_t func_offset = 0;
  uint64_t address = 0;

  // Handle function+offset syntax.
  auto plus_pos = func.find('+');
  if (plus_pos != std::string::npos) {
    if (uprobe_type_ == UprobeType::uretprobe) {
      return make_error<ParseError>(this, str, "uretprobes cannot use offsets");
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

  AttachPointList results;

  // Check for wildcards and expand if needed.
  if (util::has_wildcard(target) || util::has_wildcard(func)) {
    // Get the real paths to search
    std::vector<std::string> real_paths;
    if (target == "*") {
      if (pid.has_value()) {
        auto mapped_paths = util::get_mapped_paths_for_pid(*pid);
        if (mapped_paths) {
          real_paths = *mapped_paths;
        }
      }
    } else if (target.find('*') != std::string::npos) {
      real_paths = util::resolve_binary_path(target, pid);
    } else {
      real_paths.push_back(target);
    }

    // Process each binary path
    for (const auto &real_path : real_paths) {
      // Use blazesym to get symbols
      auto path_syms = get_symbols_from_binary(real_path);
      if (path_syms.empty()) {
        continue; // Skip on error
      }

      // Prepare wildcard matching
      bool start_wildcard, end_wildcard;
      auto tokens = util::get_wildcard_tokens(func,
                                              start_wildcard,
                                              end_wildcard);

      // Check if we need parameter truncation for demangling
      auto has_parameter = [](const std::string &token) {
        return token.find('(') != std::string::npos;
      };
      const bool truncate_parameters = enable_demangling &&
                                       std::ranges::none_of(tokens,
                                                            has_parameter);

      // Check each symbol
      for (const auto &symbol_name : path_syms) {
        bool matched = false;

        // Try direct match first
        if (util::wildcard_match(
                symbol_name, tokens, start_wildcard, end_wildcard)) {
          matched = true;
        }
        // Try demangled match if C++ demangling is enabled
        else if (enable_demangling &&
                 util::symbol_has_cpp_mangled_signature(symbol_name)) {
          char *demangled_name = cxxdemangle(symbol_name.c_str());
          if (demangled_name) {
            SCOPE_EXIT
            {
              ::free(demangled_name);
            };

            std::string match_line = demangled_name;
            if (truncate_parameters) {
              util::erase_parameter_list(match_line);
            }

            if (util::wildcard_match(
                    match_line, tokens, start_wildcard, end_wildcard)) {
              matched = true;
            }
          }
        }

        if (matched) {
          // Skip .part.N variants as they can't be traced
          if (symbol_name.find(".part.") != std::string::npos) {
            continue;
          }

          results.emplace_back(std::make_unique<UprobeAttachPoint>(
              real_path, symbol_name, func_offset, address));
        }
      }
    }
  } else {
    // No wildcards, single target/function
    results.emplace_back(std::make_unique<UprobeAttachPoint>(
        target, func, func_offset, address));
  }

  if (!util::has_wildcard(str) && results.empty()) {
    return make_error<ParseError>(this, str, "function not found");
  }

  return results;
}

Result<AttachedProbeList> UprobeProviderBase::attach_single(
    std::unique_ptr<AttachPoint> &&attach_point,
    const BpfProgram &prog,
    std::optional<int> pid) const
{
  auto &uprobe_attach_point = attach_point->as<UprobeAttachPoint>();

  auto offset_result = resolve_symbol_blazesym(uprobe_attach_point.target,
                                               uprobe_attach_point.func,
                                               uprobe_attach_point.func_offset);
  if (!offset_result) {
    return make_error<AttachError>(this,
                                   std::move(attach_point),
                                   "failed to resolve symbol " +
                                       uprobe_attach_point.func);
  }
  uint64_t offset = *offset_result;

  struct bpf_uprobe_opts opts = {};
  opts.sz = sizeof(opts);
  opts.retprobe = uprobe_type_ == UprobeType::uretprobe;

  auto *link = bpf_program__attach_uprobe_opts(
      prog.bpf_prog(),
      pid.value_or(-1),
      uprobe_attach_point.target.c_str(),
      offset,
      &opts);

  if (!link) {
    return make_error<AttachError>(this,
                                   std::move(attach_point),
                                   "failed to attach uprobe");
  }

  return make_list<AttachedProbe>(link, wrap_list(std::move(attach_point)));
}

Result<AttachedProbeList> UprobeProviderBase::attach_multi(
    AttachPointList &&attach_points,
    const BpfProgram &prog,
    std::optional<int> pid) const
{
  if (attach_points.empty()) {
    return AttachedProbeList{};
  }

  // Group attach points by target binary for efficient multi-attach
  std::unordered_map<std::string, AttachPointList> targets;
  for (auto &attach_point : attach_points) {
    auto &uprobe_attach_point = attach_point->as<UprobeAttachPoint>();
    std::string target = uprobe_attach_point.target;
    targets[target].emplace_back(std::move(attach_point));
  }

  AttachedProbeList results;
  for (auto &[target, target_attach_points] : targets) {
    // Collect function symbols for multi-attach
    std::vector<const char *> syms;
    std::vector<std::string> func_names;
    for (auto &attach_point : target_attach_points) {
      auto &uprobe_attach_point = attach_point->as<UprobeAttachPoint>();
      func_names.push_back(uprobe_attach_point.func);
      syms.push_back(func_names.back().c_str());
    }

    // Set up multi-attach options
    struct bpf_uprobe_multi_opts opts = {};
    opts.sz = sizeof(opts);
    opts.syms = syms.data();
    opts.cnt = syms.size();
    opts.retprobe = uprobe_type_ == UprobeType::uretprobe;

    auto *link = bpf_program__attach_uprobe_multi(
        prog.bpf_prog(), pid.value_or(-1), target.c_str(), nullptr, &opts);
    if (!link) {
      return make_error<AttachError>(this,
                                     std::move(target_attach_points[0]),
                                     "failed to attach multi uprobe");
    }
    results.emplace_back(
        std::make_unique<AttachedProbe>(link, std::move(target_attach_points)));
  }

  return results;
}

} // namespace bpftrace::providers

CEREAL_REGISTER_TYPE(bpftrace::providers::UprobeAttachPoint)
CEREAL_REGISTER_POLYMORPHIC_RELATION(bpftrace::providers::AttachPoint,
                                     bpftrace::providers::UprobeAttachPoint)
