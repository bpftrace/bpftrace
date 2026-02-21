#include <algorithm>
#include <dirent.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "bpftrace.h"
#include "btf.h"
#include "cxxdemangler/cxxdemangler.h"
#include "dwarf_parser.h"
#include "log.h"
#include "probe_matcher.h"
#include "scopeguard.h"
#include "symbols/kernel.h"
#include "tracefs/tracefs.h"
#include "util/paths.h"
#include "util/strings.h"
#include "util/symbols.h"
#include "util/wildcard.h"

namespace bpftrace {

// Finds all matches of search_input in the provided input stream.
std::set<std::string> ProbeMatcher::get_matches_in_stream(
    const std::string& search_input,
    std::istream& symbol_stream,
    bool demangle_symbols,
    const char delim)
{
  bool start_wildcard, end_wildcard;
  auto tokens = util::get_wildcard_tokens(search_input,
                                          start_wildcard,
                                          end_wildcard);

  // Since demangled_name contains function parameters, we need to remove
  // them unless the user specified '(' in the search input (i.e. wants
  // to match against the parameters explicitly).
  // Only used for C++ when demangling is enabled.
  auto has_parameter = [](const std::string& token) {
    return token.find('(') != std::string::npos;
  };
  const bool truncate_parameters = std::ranges::none_of(tokens,

                                                        has_parameter);

  std::string line;
  std::set<std::string> matches;
  while (std::getline(symbol_stream, line, delim)) {
    if (!util::wildcard_match(line, tokens, start_wildcard, end_wildcard)) {
      if (demangle_symbols) {
        auto fun_line = line;
        auto prefix = fun_line.find(':') != std::string::npos
                          ? util::erase_prefix(fun_line) + ":"
                          : "";
        if (util::symbol_has_cpp_mangled_signature(fun_line)) {
          char* demangled_name = cxxdemangle(fun_line.c_str());
          if (!demangled_name)
            continue;
          SCOPE_EXIT
          {
            ::free(demangled_name);
          };

          // Match against the demanled name.
          std::string match_line = prefix + demangled_name;
          if (truncate_parameters) {
            util::erase_parameter_list(match_line);
          }

          if (util::wildcard_match(
                  match_line, tokens, start_wildcard, end_wildcard)) {
            goto out;
          }
        }
      }
      continue;
    }
  out:
    // skip the ".part.N" kprobe variants, as they can't be traced:
    if (line.find(".part.") != std::string::npos)
      continue;

    matches.insert(line);
  }
  return matches;
}

// Get matches of search_input (containing a wildcard) for a given probe_type.
// probe_type determines where to take the candidate matches from.
// Some probe types (e.g. uprobe) require target to be specified.
std::set<std::string> ProbeMatcher::get_matches_for_probetype(
    const ProbeType& probe_type,
    const std::string& target,
    const std::string& search_input,
    bool demangle_symbols)
{
  std::unique_ptr<std::istream> symbol_stream;

  switch (probe_type) {
    case ProbeType::kprobe:
    case ProbeType::kretprobe: {
      if (target.empty()) {
        symbol_stream = get_symbols_from_traceable_funcs(false);
      } else if (!util::has_wildcard(target)) {
        symbol_stream = get_symbols_from_traceable_funcs(true, target);
      } else {
        symbol_stream = get_symbols_from_traceable_funcs(true);
      }
      break;
    }
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::watchpoint: {
      auto result = [&]() {
        if (bpftrace_->pid()) {
          auto pid_symbols = user_func_info_.func_symbols_for_pid(
              *bpftrace_->pid());
          if (pid_symbols) {
            return *pid_symbols;
          }
        }
        return symbols::BinaryFuncMap();
      }();
      // Expand to the full set of possible matching paths.
      auto paths = util::resolve_binary_path(target, bpftrace_->pid());
      for (const auto& path : paths) {
        auto ok = user_func_info_.func_symbols_for_path(path);
        if (ok) {
          for (const auto& sym : *ok) {
            result[path].insert(sym);
          }
        }
      }
      std::stringstream ss;
      for (const auto& [path, symbols] : result) {
        for (const auto& sym : symbols) {
          ss << path << ":" << sym << "\n";
        }
      }
      symbol_stream = std::make_unique<std::istringstream>(ss.str());
      break;
    }
    case ProbeType::tracepoint: {
      auto result = kernel_func_info_.get_tracepoints();
      std::stringstream ss;
      for (const auto& [category, events] : result) {
        for (const auto& event : *events) {
          ss << category << ":" << event << "\n";
        }
      }
      symbol_stream = std::make_unique<std::istringstream>(ss.str());
      break;
    }
    case ProbeType::rawtracepoint: {
      symbol_stream = get_raw_tracepoint_symbols();
      break;
    }
    case ProbeType::fentry:
    case ProbeType::fexit: {
      if (target == "bpf") {
        symbol_stream = get_running_bpf_programs();
      } else {
        symbol_stream = get_fentry_symbols(target);
      }
      break;
    }
    case ProbeType::usdt: {
      // If pid is set, then we grab symbols directly from the binary.
      auto result = [&]() {
        if (bpftrace_->pid()) {
          auto pid_symbols = user_func_info_.usdt_probes_for_pid(
              *bpftrace_->pid());
          if (pid_symbols) {
            return *pid_symbols;
          }
        }
        return symbols::BinaryUSDTMap();
      }();
      // Like the uprobe case above, we expand to the full set of paths.
      auto paths = util::resolve_binary_path(target, bpftrace_->pid());
      for (const auto& path : paths) {
        auto ok = user_func_info_.usdt_probes_for_path(path);
        if (ok) {
          for (const auto& sym : *ok) {
            result[path].insert(sym);
          }
        }
      }
      std::stringstream ss;
      for (const auto& [path, symbols] : result) {
        for (const auto& sym : symbols) {
          ss << path << ":" << sym.provider << ":" << sym.name + "\n";
        }
      }
      symbol_stream = std::make_unique<std::istringstream>(ss.str());
      break;
    }
    case ProbeType::software: {
      symbol_stream = get_symbols_from_list(SW_PROBE_LIST);
      break;
    }
    case ProbeType::hardware: {
      symbol_stream = get_symbols_from_list(HW_PROBE_LIST);
      break;
    }
    case ProbeType::iter: {
      std::string ret;
      auto iters = bpftrace_->btf_->get_all_iters();
      for (const auto& iter : iters) {
        // second check
        if (bpftrace_->feature_->has_iter(iter))
          ret += iter + "\n";
        else
          LOG(WARNING) << "The kernel contains bpf_iter__" << iter
                       << " struct but does not support loading an iterator"
                          " program against it. Please report this bug.";
      }
      symbol_stream = std::make_unique<std::istringstream>(ret);
      break;
    }
    case ProbeType::interval:
    case ProbeType::profile: {
      std::string ret;
      for (const auto& unit : TIME_UNITS)
        ret += unit + ":\n";
      symbol_stream = std::make_unique<std::istringstream>(ret);
      break;
    }
    case ProbeType::special:
    case ProbeType::test:
    case ProbeType::benchmark:
      return { target + ":" };
    default:
      return {};
  }

  if (symbol_stream)
    return get_matches_in_stream(search_input,
                                 *symbol_stream,
                                 demangle_symbols);
  else
    return {};
}

// Find all matches of search_input in set
std::set<std::string> ProbeMatcher::get_matches_in_set(
    const std::string& search_input,
    const std::set<std::string>& set)
{
  std::string stream_in;
  // Strings in the set may contain a newline character, so we use '$'
  // as a delimiter.
  for (const auto& str : set)
    stream_in.append(str + "$");

  std::istringstream stream(stream_in);
  return get_matches_in_stream(search_input, stream, false, '$');
}

std::unique_ptr<std::istream> ProbeMatcher::get_symbols_from_traceable_funcs(
    bool with_modules,
    std::optional<std::string> module) const
{
  std::stringstream ss;
  for (const auto& [mod, funcs] :
       kernel_func_info_.get_traceable_funcs(module)) {
    for (const auto& func : *funcs) {
      if (with_modules) {
        ss << mod << ":" << func << "\n";
      } else {
        ss << func << "\n";
      }
    }
  }
  return std::make_unique<std::istringstream>(ss.str());
}

std::unique_ptr<std::istream> ProbeMatcher::get_fentry_symbols(
    [[maybe_unused]] const std::string& mod) const
{
  return bpftrace_->btf_->get_all_traceable_funcs(kernel_func_info_);
}

std::unique_ptr<std::istream> ProbeMatcher::get_running_bpf_programs() const
{
  std::string funcs;
  auto ids_and_syms = kernel_func_info_.get_bpf_progs();
  for (const auto& [id, symbol] : ids_and_syms) {
    funcs += "bpf:" + std::to_string(id) + ":" + symbol + "\n";
  }
  return std::make_unique<std::istringstream>(funcs);
}

std::unique_ptr<std::istream> ProbeMatcher::get_raw_tracepoint_symbols() const
{
  if (bpftrace_->btf_->objects_cnt() > 1) {
    return bpftrace_->btf_->get_all_raw_tracepoints();
  } else {
    std::string rts;
    for (const auto& [module, events] :
         kernel_func_info_.get_raw_tracepoints()) {
      for (const auto& event : *events) {
        rts += module + ":" + event + "\n";
      }
    }
    return std::make_unique<std::istringstream>(rts);
  }
}

std::unique_ptr<std::istream> ProbeMatcher::get_symbols_from_list(
    const std::vector<ProbeListItem>& probes_list) const
{
  std::string symbols;
  for (const auto& probe : probes_list) {
    symbols += probe.path + ":\n";
    if (!probe.alias.empty())
      symbols += probe.alias + ":\n";
  }
  return std::make_unique<std::istringstream>(symbols);
}

// Get list of kernel probe types for the purpose of listing.
// Ignore return probes and aliases.
std::unique_ptr<std::istream> ProbeMatcher::kernel_probe_list()
{
  std::string probes;
  for (const auto& p : PROBE_LIST) {
    if (!p.show_in_kernel_list) {
      continue;
    }
    probes += p.name + "\n";
  }

  return std::make_unique<std::istringstream>(probes);
}

// Get list of userspace probe types for the purpose of listing.
// Ignore return probes.
std::unique_ptr<std::istream> ProbeMatcher::userspace_probe_list()
{
  std::string probes;
  for (const auto& p : PROBE_LIST) {
    if (p.show_in_userspace_list) {
      probes += p.name + "\n";
    }
  }

  return std::make_unique<std::istringstream>(probes);
}

FuncParamLists ProbeMatcher::get_tracepoints_params(
    const std::set<std::string>& tracepoints)
{
  FuncParamLists params;
  for (const auto& tracepoint : tracepoints) {
    auto event = tracepoint;
    auto category = util::erase_prefix(event);

    std::string format_file_path = tracefs::event_format_file(category, event);
    std::ifstream format_file(format_file_path.c_str());
    std::string line;

    if (format_file.fail()) {
      LOG(ERROR) << "tracepoint format file not found: " << format_file_path;
      return {};
    }

    // Skip lines until the first empty line
    do {
      getline(format_file, line);
    } while (!line.empty());

    while (getline(format_file, line)) {
      if (line.starts_with("\tfield:")) {
        size_t col_pos = line.find(':') + 1;
        params[tracepoint].push_back(
            line.substr(col_pos, line.find(';') - col_pos));
      }
    }
  }
  return params;
}

FuncParamLists ProbeMatcher::get_iters_params(
    const std::set<std::string>& iters)
{
  const std::string prefix = "vmlinux:bpf_iter_";
  FuncParamLists params;
  std::set<std::string> funcs;

  for (const auto& iter : iters)
    funcs.insert(prefix + iter);

  params = bpftrace_->btf_->get_params(funcs);
  for (auto func : funcs) {
    // delete `int retval`
    params[func].pop_back();
    // delete `struct bpf_iter_meta * meta`
    params[func].erase(params[func].begin());
    // restore key value
    auto param = params.extract(func);
    param.key() = func.substr(prefix.size());
    params.insert(std::move(param));
  }
  return params;
}

FuncParamLists ProbeMatcher::get_uprobe_params(
    const std::set<std::string>& uprobes)
{
  FuncParamLists params;
  static std::set<std::string> warned_paths;

  for (const auto& match : uprobes) {
    std::string fun = match;
    std::string path = util::erase_prefix(fun);
    auto dwarf = Dwarf::GetFromBinary(nullptr, path);
    if (dwarf)
      params.emplace(match, dwarf->get_function_params(fun));
    else {
      if (warned_paths.insert(path).second)
        LOG(WARNING) << "No DWARF found for \"" << path << "\""
                     << ", cannot show parameter info";
    }
  }

  return params;
}

FuncParamLists ProbeMatcher::get_params_for_matches(
    ProbeType probe_type,
    const std::set<std::string>& matches)
{
  if (!bt_verbose)
    return {};

  switch (probe_type) {
    case ProbeType::tracepoint:
      return get_tracepoints_params(matches);
    case ProbeType::fentry:
    case ProbeType::fexit:
      return bpftrace_->btf_->get_params(matches);
    case ProbeType::rawtracepoint:
      return bpftrace_->btf_->get_rawtracepoint_params(matches);
    case ProbeType::iter:
      return get_iters_params(matches);
    case ProbeType::uprobe:
      return get_uprobe_params(matches);
    case ProbeType::kprobe:
      return bpftrace_->btf_->get_kprobes_params(matches);
    case ProbeType::kretprobe:
      return bpftrace_->btf_->get_kretprobes_params(matches);
    default:
      return {};
  }
}

void ProbeMatcher::format_matches_for_listing(
    ProbeType probe_type,
    const std::set<std::string>& matches,
    const FuncParamLists& param_lists,
    std::vector<std::string>& results,
    const std::string& lang)
{
  for (const auto& match : matches) {
    std::string match_print = match;
    if (lang == "cpp") {
      std::string target = util::erase_prefix(match_print);
      char* demangled_name = cxxdemangle(match_print.c_str());
      SCOPE_EXIT
      {
        ::free(demangled_name);
      };

      // Demangled name may contain symbols not accepted by the attach
      // point parser, so surround it with quotes to make the entry
      // directly usable as an attach point.
      auto func = demangled_name ? "\"" + std::string(demangled_name) + "\""
                                 : match_print;
      match_print = target + ":" + lang + ":" + func;
    }

    std::ostringstream ss;
    ss << probe_type << ":" << match_print;
    results.push_back(ss.str());
    if (bt_verbose) {
      auto it = param_lists.find(match);
      if (it != param_lists.end()) {
        for (const auto& param : it->second)
          results.push_back("    " + param);
      }
    }
  }
}

std::vector<std::string> ProbeMatcher::get_probes_for_listing(
    ast::Program* prog)
{
  std::vector<std::string> results;
  for (auto* probe : prog->probes) {
    for (auto* ap : probe->attach_points) {
      auto probe_type = probetype(ap->provider);
      // Skip special probes (begin, end, self).
      if (probe_type == ProbeType::special)
        continue;

      auto matches = get_matches_for_ap(*ap);
      auto param_lists = get_params_for_matches(probe_type, matches);
      format_matches_for_listing(
          probe_type, matches, param_lists, results, ap->lang);
    }
  }
  return results;
}

std::vector<std::string> ProbeMatcher::get_probes_for_listing(
    const std::string& pattern,
    std::optional<pid_t> pid)
{
  std::vector<std::string> results;

  // Split the pattern by ':' to extract probe type and search components.
  // Pattern format: "probe_type:target:func" or "probe_type:func" etc.
  auto parts = util::split_string(pattern, ':');
  if (parts.empty()) {
    return results;
  }

  // Build the search input from remaining parts.
  std::string search_suffix;
  auto colon_pos = pattern.find(':');
  if (colon_pos != std::string::npos) {
    search_suffix = pattern.substr(colon_pos + 1);
  }
  if (search_suffix.empty() && parts.size() == 1) {
    search_suffix = "*";
  }

  // Determine which probe types to search.
  std::set<std::string> probe_types;
  const auto& probe_type_pattern = parts[0];
  // Include userspace probe types only if:
  // 1. The probe type is explicitly specified (not wildcarded), OR
  // 2. A PID is provided to scope the search, OR
  // 3. A specific (non-wildcarded) target file exists to scope the search
  bool has_specific_target = parts.size() > 1 && !parts[1].empty() &&
                             !util::has_wildcard(parts[1]) &&
                             std::filesystem::exists(parts[1]);
  bool include_userspace = (!util::has_wildcard(probe_type_pattern) &&
                            !probe_type_pattern.empty()) ||
                           pid.has_value() || has_specific_target;

  // For single-part patterns (like "*" or "kprobe"), expand probe types.
  if (util::has_wildcard(probe_type_pattern) || parts.size() == 1) {
    // Expand to all matching probe types.
    auto kernel_types = expand_probetype_kernel(
        probe_type_pattern.empty() ? "*" : probe_type_pattern);
    probe_types.insert(kernel_types.begin(), kernel_types.end());
    if (include_userspace) {
      auto userspace_types = expand_probetype_userspace(
          probe_type_pattern.empty() ? "*" : probe_type_pattern);
      probe_types.insert(userspace_types.begin(), userspace_types.end());
    }
  } else {
    probe_types.insert(expand_probe_name(probe_type_pattern));
  }

  for (const auto& probe_type_str : probe_types) {
    auto probe_type = probetype(probe_type_str);
    if (probe_type == ProbeType::invalid)
      continue;

    std::string target;
    std::string search_input = search_suffix;

    // For probe types that require a target, extract it from search_suffix.
    switch (probe_type) {
      case ProbeType::uprobe:
      case ProbeType::uretprobe:
      case ProbeType::usdt:
      case ProbeType::tracepoint: {
        // These need target:func format.
        if (parts.size() > 2) {
          target = parts[1];
          search_input = search_suffix;
        } else {
          target = "*";
          search_input = "*:" + search_suffix;
        }
        break;
      }
      case ProbeType::kprobe:
      case ProbeType::kretprobe:
      case ProbeType::fentry:
      case ProbeType::fexit:
      case ProbeType::rawtracepoint: {
        // These can be target:func or just func.
        if (parts.size() > 2) {
          target = parts[1];
        }
        search_input = search_suffix;
        break;
      }
      default:
        // For other probe types, use search_suffix as-is.
        search_input = search_suffix.empty() ? "*" : search_suffix;
        break;
    }

    auto matches = get_matches_for_probetype(
        probe_type, target, search_input, false /* demangle_symbols */);

    auto param_lists = get_params_for_matches(probe_type, matches);
    format_matches_for_listing(probe_type, matches, param_lists, results);
  }
  return results;
}

std::set<std::string> ProbeMatcher::get_matches_for_ap(
    const ast::AttachPoint& attach_point)
{
  std::string search_input;
  switch (probetype(attach_point.provider)) {
    case ProbeType::kprobe:
    case ProbeType::kretprobe: {
      if (!attach_point.target.empty())
        search_input = attach_point.target + ":" + attach_point.func;
      else
        search_input = attach_point.func;
      break;
    }
    case ProbeType::rawtracepoint: {
      search_input = attach_point.target + ":" + attach_point.func;
      break;
    }
    case ProbeType::iter: {
      search_input = attach_point.func;
      break;
    }
    case ProbeType::fentry:
    case ProbeType::fexit: {
      if (attach_point.target == "bpf") {
        search_input = "bpf:" +
                       (attach_point.bpf_prog_id
                            ? std::to_string(attach_point.bpf_prog_id)
                            : "*") +
                       ":" + attach_point.func;
        break;
      }
      [[fallthrough]];
    }
    case ProbeType::special:
    case ProbeType::test:
    case ProbeType::benchmark:
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::tracepoint: {
      // Do not expand "target:" as that would match all functions in
      // target. This may occur when an absolute address is given instead of
      // a function.
      if (attach_point.func.empty())
        return { attach_point.target + ":" };

      search_input = attach_point.target + ":" + attach_point.func;
      break;
    }
    case ProbeType::hardware:
    case ProbeType::software:
    case ProbeType::profile:
    case ProbeType::interval:
    case ProbeType::watchpoint: {
      search_input = attach_point.target + ":";
      break;
    }
    case ProbeType::usdt: {
      auto target = attach_point.target;
      // If PID is specified, targets in symbol_stream may have the
      // "/proc/<PID>/root" prefix followed by an absolute path, so we make
      // the target absolute and add a leading wildcard.
      if (bpftrace_->pid().has_value()) {
        if (!target.empty()) {
          if (auto abs_target = util::abs_path(target))
            target = "*" + abs_target.value();
        } else
          target = "*";
      }
      auto ns = attach_point.ns.empty() ? "*" : attach_point.ns;
      search_input = target + ":" + ns + ":" + attach_point.func;
      break;
    }
    case ProbeType::invalid:
      throw WildcardException(
          "Wildcard matches aren't available on probe type '" +
          attach_point.provider + "'");
  }

  return get_matches_for_probetype(probetype(attach_point.provider),
                                   attach_point.target,
                                   search_input,
                                   attach_point.lang == "cpp");
}

std::set<std::string> ProbeMatcher::expand_probetype_kernel(
    const std::string& probe_type)
{
  if (util::has_wildcard(probe_type))
    return get_matches_in_stream(probe_type, *kernel_probe_list());
  else
    return { probe_type };
}

std::set<std::string> ProbeMatcher::expand_probetype_userspace(
    const std::string& probe_type)
{
  if (util::has_wildcard(probe_type))
    return get_matches_in_stream(probe_type, *userspace_probe_list());
  else
    return { probe_type };
}

std::vector<std::string> ProbeMatcher::get_structs_for_listing(
    const std::string& search)
{
  std::vector<std::string> results;
  auto structs = bpftrace_->btf_->get_all_structs();

  std::string search_input = search;
  // If verbose is on, structs will contain full definitions
  if (bt_verbose)
    search_input += " *{*}*";

  for (const auto& match : get_matches_in_set(search_input, structs))
    results.push_back(match);
  return results;
}
} // namespace bpftrace
