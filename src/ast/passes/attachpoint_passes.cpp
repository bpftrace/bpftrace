#include <algorithm>
#include <bcc/bcc_proc.h>
#include <cctype>
#include <iostream>
#include <string>
#include <vector>

#include "arch/arch.h"
#include "ast/ast.h"
#include "ast/context.h"
#include "ast/helpers.h"
#include "ast/passes/attachpoint_passes.h"
#include "ast/visitor.h"
#include "probe_matcher.h"
#include "symbols/kernel.h"
#include "util/int_parser.h"
#include "util/paths.h"
#include "util/strings.h"
#include "util/system.h"
#include "util/wildcard.h"

namespace bpftrace::ast {

class AttachPointChecker : public Visitor<AttachPointChecker> {
public:
  explicit AttachPointChecker(BPFtrace &bpftrace, FunctionInfo &func_info_state)
      : bpftrace_(bpftrace), func_info_state_(func_info_state) {};

  using Visitor<AttachPointChecker>::visit;
  void visit(AttachPoint &ap);

private:
  BPFtrace &bpftrace_;
  FunctionInfo &func_info_state_;
  std::unordered_map<std::string, Location> test_locs_;
  std::unordered_map<std::string, Location> benchmark_locs_;
};

void AttachPointChecker::visit(AttachPoint &ap)
{
  if (ap.provider == "kprobe" || ap.provider == "kretprobe") {
    if (ap.func.empty())
      ap.addError() << "kprobes should be attached to a function";
    // Warn if user tries to attach to a non-traceable function
    if (bpftrace_.config_->missing_probes != ConfigMissingProbes::ignore &&
        !util::has_wildcard(ap.func) &&
        !func_info_state_.kernel_info().is_traceable(ap.func)) {
      ap.addWarning() << ap.func
                      << " is not traceable (either non-existing, inlined, "
                         "or marked as "
                         "\"notrace\"); attaching to it will likely fail";
    }
  } else if (ap.provider == "uprobe" || ap.provider == "uretprobe") {
    if (ap.target.empty())
      ap.addError() << ap.provider << " should have a target";
    if (ap.func.empty() && ap.address == 0)
      ap.addError() << ap.provider
                    << " should be attached to a function and/or address";
    if (!ap.lang.empty() && !is_supported_lang(ap.lang))
      ap.addError() << "unsupported language type: " << ap.lang;

    if (ap.provider == "uretprobe" && ap.func_offset != 0)
      ap.addError() << "uretprobes can not be attached to a function offset";

    auto get_paths = [&]() -> Result<std::vector<std::string>> {
      const auto pid = bpftrace_.pid();
      if (ap.target == "*") {
        if (pid.has_value())
          return util::get_mapped_paths_for_pid(*pid);
        else
          return util::get_mapped_paths_for_running_pids();
      } else {
        return util::resolve_binary_path(ap.target, pid);
      }
    };
    auto paths = get_paths();
    if (!paths) {
      // There was an error during path resolution.
      ap.addError() << "error finding uprobe target: " << paths.takeError();
    } else {
      switch (paths->size()) {
        case 0:
          ap.addError() << "uprobe target file '" << ap.target
                        << "' does not exist or is not executable";
          break;
        case 1:
          // Replace the glob at this stage only if this is *not* a wildcard,
          // otherwise we rely on the probe matcher. This is not going through
          // any interfaces that can be properly mocked.
          if (ap.target.find("*") == std::string::npos)
            ap.target = paths->front();
          break;
        default:
          // If we are doing a PATH lookup (ie not glob), we follow shell
          // behavior and take the first match.
          // Otherwise we keep the target with glob, it will be expanded later
          if (ap.target.find("*") == std::string::npos) {
            ap.addWarning() << "attaching to uprobe target file '"
                            << paths->front() << "' but matched "
                            << std::to_string(paths->size()) << " binaries";
            ap.target = paths->front();
          }
      }
    }
  } else if (ap.provider == "usdt") {
    bpftrace_.has_usdt_ = true;
    if (ap.func.empty())
      ap.addError() << "usdt probe must have a target function or wildcard";

    if (!ap.target.empty() &&
        !(bpftrace_.pid().has_value() && util::has_wildcard(ap.target))) {
      auto paths = util::resolve_binary_path(ap.target, bpftrace_.pid());
      switch (paths.size()) {
        case 0:
          ap.addError() << "usdt target file '" << ap.target
                        << "' does not exist or is not executable";
          break;
        case 1:
          // See uprobe, above.
          if (ap.target.find("*") == std::string::npos)
            ap.target = paths.front();
          break;
        default:
          // See uprobe, above.
          if (ap.target.find("*") == std::string::npos) {
            ap.addWarning() << "attaching to usdt target file '"
                            << paths.front() << "' but matched "
                            << std::to_string(paths.size()) << " binaries";
            ap.target = paths.front();
          }
      }
    }

    const auto pid = bpftrace_.pid();
    if (pid.has_value()) {
      auto ok = func_info_state_.user_info().usdt_probes_for_pid(*pid);
      if (!ok) {
        ap.addError() << ok.takeError();
      }
    } else if (ap.target == "*") {
      auto ok = func_info_state_.user_info().usdt_probes_for_all_pids();
      if (!ok) {
        ap.addError() << ok.takeError();
      }
    } else if (!ap.target.empty()) {
      for (auto &path : util::resolve_binary_path(ap.target)) {
        auto ok = func_info_state_.user_info().usdt_probes_for_path(path);
        if (!ok) {
          ap.addError() << ok.takeError();
        }
      }
    } else {
      ap.addError() << "usdt probe must specify at least path or pid to "
                       "probe. To target "
                       "all paths/pids set the path to '*'.";
    }
  } else if (ap.provider == "tracepoint") {
    if (ap.target.empty() || ap.func.empty())
      ap.addError() << "tracepoint probe must have a target";
  } else if (ap.provider == "rawtracepoint") {
    if (ap.func.empty())
      ap.addError() << "rawtracepoint should be attached to a function";

    if (!bpftrace_.has_btf_data()) {
      ap.addError() << "rawtracepoints require kernel BTF. Try using a "
                       "'tracepoint' instead.";
    }

  } else if (ap.provider == "profile") {
    if (ap.target.empty())
      ap.addError() << "profile probe must have unit of time";
    else {
      if (!TIME_UNITS.contains(ap.target))
        ap.addError() << ap.target << " is not an accepted unit of time";
      if (!ap.func.empty())
        ap.addError() << "profile probe must have an integer frequency";
      else if (ap.freq <= 0)
        ap.addError() << "profile frequency should be a positive integer";
    }
  } else if (ap.provider == "interval") {
    if (ap.target.empty())
      ap.addError() << "interval probe must have unit of time";
    else {
      if (!TIME_UNITS.contains(ap.target))
        ap.addError() << ap.target << " is not an accepted unit of time";
      if (!ap.func.empty())
        ap.addError() << "interval probe must have an integer frequency";
      else if (ap.freq <= 0)
        ap.addError() << "interval frequency should be a positive integer";
    }
  } else if (ap.provider == "software") {
    if (ap.target.empty()) {
      ap.addError() << "software probe must have a software event name";
    } else {
      if (!util::has_wildcard(ap.target) && !ap.ignore_invalid) {
        bool found = false;
        for (const auto &probeListItem : SW_PROBE_LIST) {
          if (ap.target == probeListItem.path ||
              (!probeListItem.alias.empty() &&
               ap.target == probeListItem.alias)) {
            found = true;
            break;
          }
        }
        if (!found) {
          ap.addError() << ap.target << " is not a software probe";
        }
      } else if (util::has_wildcard(ap.target)) {
        ap.addError() << "wildcards are not allowed for software probe type";
      }
    }
    if (!ap.func.empty()) {
      ap.addError() << "software probe can only have an integer count";
    } else if (ap.freq < 0) {
      ap.addError() << "software count should be a positive integer";
    }
  } else if (ap.provider == "watchpoint") {
    if (!ap.address) {
      ap.addError() << "watchpoint must be attached to a non-zero address";
    }
    if (ap.len != 1 && ap.len != 2 && ap.len != 4 && ap.len != 8) {
      ap.addError() << "watchpoint length must be one of (1,2,4,8)";
    }
    if (ap.mode.empty())
      ap.addError() << "watchpoint mode must be combination of (r,w,x)";
    std::ranges::sort(ap.mode);
    for (const char c : ap.mode) {
      if (c != 'r' && c != 'w' && c != 'x')
        ap.addError() << "watchpoint mode must be combination of (r,w,x)";
    }
    for (size_t i = 1; i < ap.mode.size(); ++i) {
      if (ap.mode[i - 1] == ap.mode[i])
        ap.addError() << "watchpoint modes may not be duplicated";
    }
    const auto &modes = arch::Host::watchpoint_modes();
    if (!modes.contains(ap.mode)) {
      if (modes.empty()) {
        // There are no valid modes.
        ap.addError() << "watchpoints not supported";
      } else {
        // Build a suitable error with hint.
        auto &err = ap.addError();
        err << "invalid watchpoint mode: " << ap.mode;
        err.addHint() << "supported modes: "
                      << util::str_join(std::vector(modes.begin(), modes.end()),
                                        ",");
      }
    }
  } else if (ap.provider == "hardware") {
    if (ap.target.empty()) {
      ap.addError() << "hardware probe must have a hardware event name";
    } else {
      if (!util::has_wildcard(ap.target) && !ap.ignore_invalid) {
        bool found = false;
        for (const auto &probeListItem : HW_PROBE_LIST) {
          if (ap.target == probeListItem.path ||
              (!probeListItem.alias.empty() &&
               ap.target == probeListItem.alias)) {
            found = true;
            break;
          }
        }
        if (!found) {
          ap.addError() << ap.target + " is not a hardware probe";
        }
      } else if (util::has_wildcard(ap.target)) {
        ap.addError() << "wildcards are not allowed for hardware probe type";
      }
    }
    if (!ap.func.empty()) {
      ap.addError() << "hardware probe can only have an integer count";
    } else if (ap.freq < 0) {
      ap.addError() << "hardware frequency should be a positive integer";
    }
  } else if (ap.provider == "begin" || ap.provider == "end") {
    if (!ap.target.empty() || !ap.func.empty()) {
      ap.addError() << "begin/end probes should not have a target";
    }
  } else if (ap.provider == "self") {
    if (ap.target == "signal") {
      if (!SIGNALS.contains(ap.func))
        ap.addError() << ap.func << " is not a supported signal";
      return;
    }
    ap.addError() << ap.target << " is not a supported trigger";
  } else if (ap.provider == "test") {
    if (ap.target.empty())
      ap.addError() << "test probes must have a name";
    auto it = test_locs_.find(ap.target);

    if (it != test_locs_.end()) {
      auto &err = ap.addError();
      err << "\"" + ap.target + "\""
          << " was used as the name for more than one TEST probe";
      err.addContext(it->second) << "this is the other instance";
    }

    test_locs_.emplace(ap.target, ap.loc);
  } else if (ap.provider == "bench") {
    if (ap.target.empty())
      ap.addError() << "bench probes must have a name";
    auto it = benchmark_locs_.find(ap.target);

    if (it != benchmark_locs_.end()) {
      auto &err = ap.addError();
      err << "\"" + ap.target + "\""
          << " was used as the name for more than one BENCH probe";
      err.addContext(it->second) << "this is the other instance";
    }

    benchmark_locs_.emplace(ap.target, ap.loc);
  } else if (ap.provider == "fentry" || ap.provider == "fexit") {
    if (ap.func.empty())
      ap.addError() << "fentry/fexit should specify a function";
  } else if (ap.provider == "iter") {
    if (bpftrace_.btf_->has_data() &&
        !bpftrace_.btf_->get_all_iters().contains(ap.func)) {
      ap.addError() << "iter " << ap.func
                    << " not available for your kernel version.";
    }

    if (ap.func.empty())
      ap.addError() << "iter should specify a iterator's name";
  } else {
    ap.addError() << "Invalid provider: '" << ap.provider << "'";
  }
}

AttachPointParser::State AttachPointParser::argument_count_error(
    int expected,
    std::optional<int> expected2)
{
  // Subtract one for the probe type (eg kprobe)
  int found = parts_.size() - 1;

  errs_ << ap_->provider << " probe type requires " << expected;
  if (expected2.has_value()) {
    errs_ << " or " << *expected2;
  }
  errs_ << " arguments, found " << found << std::endl;

  return INVALID;
}

AttachPointParser::AttachPointParser(ASTContext &ctx,
                                     BPFtrace &bpftrace,
                                     FunctionInfo &func_info_state)
    : ctx_(ctx), bpftrace_(bpftrace), func_info_state_(func_info_state)
{
}

void AttachPointParser::parse()
{
  if (!ctx_.root)
    return;

  for (Probe *probe : ctx_.root->probes) {
    for (size_t i = 0; i < probe->attach_points.size(); ++i) {
      auto *ap_ptr = probe->attach_points[i];
      auto &ap = *ap_ptr;
      new_attach_points.clear();

      State s = parse_attachpoint(ap);
      if (s == INVALID) {
        ap.addError() << errs_.str();
      } else if (s == SKIP || s == NEW_APS) {
        // Remove the current attach point
        probe->attach_points.erase(probe->attach_points.begin() + i);
        i--;
        if (s == NEW_APS) {
          // The removed attach point is replaced by new ones
          probe->attach_points.insert(probe->attach_points.end(),
                                      new_attach_points.begin(),
                                      new_attach_points.end());
        }
      }

      // clear error buffer between attach points to prevent non-fatal errors
      // from being carried over and printed on the next fatal error
      errs_.str({});
    }

    auto it = std::ranges::remove_if(probe->attach_points,
                                     [](const AttachPoint *ap) {
                                       return ap->provider.empty();
                                     });
    probe->attach_points.erase(it.begin(), it.end());

    if (probe->attach_points.empty()) {
      const auto missing_probes = bpftrace_.config_->missing_probes;
      if (missing_probes == ConfigMissingProbes::error) {
        probe->addError() << "No attach points for probe";
      }
    }

    has_iter_ap_ = false; // reset for each probe
  }
}

AttachPointParser::State AttachPointParser::parse_attachpoint(AttachPoint &ap)
{
  ap_ = &ap;

  parts_.clear();
  if (State s = lex_attachpoint(*ap_))
    return s;

  if (parts_.empty()) {
    errs_ << "Invalid attachpoint definition" << std::endl;
    return INVALID;
  }

  auto &front = parts_.front();
  if (front.empty()) {
    // Do not fail on empty attach point, could be just a trailing comma
    ap_->provider = "";
    return OK;
  }

  // First, if there is a '=' in the provider, then this is treated
  // as a deliminator for the user-provided name.
  auto pos = front.find('=');
  if (pos != std::string::npos && pos != front.size() - 1) {
    ap.user_provided_name.emplace(front.substr(0, pos));
    front = front.substr(pos + 1);
  }

  std::set<std::string> probe_types;
  if (util::has_wildcard(front)) {
    // Single argument listing looks at all relevant probe types
    std::string probetype_query = (parts_.size() == 1) ? "*" : front;

    // Probe type expansion
    // If PID is specified or the second part of the attach point is a path
    // (contains '/'), use userspace probe types.
    // Otherwise, use kernel probe types.
    ProbeMatcher probe_matcher(&bpftrace_,
                               func_info_state_.kernel_info(),
                               func_info_state_.user_info());
    if (bpftrace_.pid().has_value() ||
        (parts_.size() >= 2 && parts_[1].find('/') != std::string::npos)) {
      probe_types = probe_matcher.expand_probetype_userspace(probetype_query);
    } else {
      probe_types = probe_matcher.expand_probetype_kernel(probetype_query);
    }
  } else
    probe_types = { front };

  if (probe_types.empty()) {
    if (util::has_wildcard(front))
      errs_ << "No probe type matched for " << front << std::endl;
    else
      errs_ << "Invalid probe type: " << front << std::endl;
    return INVALID;
  } else if (probe_types.size() > 1) {
    // If the probe type string matches more than 1 probe, create a new set of
    // attach points (one for every match) that will replace the original one.
    for (const auto &probe_type : probe_types) {
      std::string raw_input = ap.raw_input;
      if (parts_.size() > 1)
        util::erase_prefix(raw_input);
      raw_input = probe_type + ":" + raw_input;
      // New attach points have ignore_invalid set to true - probe types for
      // which raw_input has invalid number of parts will be ignored (instead
      // of throwing an error). These will have the same associated location.
      new_attach_points.push_back(
          ctx_.make_node<AttachPoint>(ap.loc, raw_input, true));
    }
    return NEW_APS;
  }

  ap.provider = expand_probe_name(*probe_types.begin());

  switch (probetype(ap.provider)) {
    case ProbeType::special:
      return special_parser();
    case ProbeType::test:
      return test_parser();
    case ProbeType::benchmark:
      return benchmark_parser();
    case ProbeType::kprobe:
      return kprobe_parser();
    case ProbeType::kretprobe:
      return kretprobe_parser();
    case ProbeType::uprobe:
      return uprobe_parser();
    case ProbeType::uretprobe:
      return uretprobe_parser();
    case ProbeType::usdt:
      return usdt_parser();
    case ProbeType::tracepoint:
      return tracepoint_parser();
    case ProbeType::profile:
      return profile_parser();
    case ProbeType::interval:
      return interval_parser();
    case ProbeType::software:
      return software_parser();
    case ProbeType::hardware:
      return hardware_parser();
    case ProbeType::watchpoint:
      return watchpoint_parser();
    case ProbeType::fentry:
    case ProbeType::fexit:
      return fentry_parser();
    case ProbeType::iter:
      return iter_parser();
    case ProbeType::rawtracepoint:
      return raw_tracepoint_parser();
    case ProbeType::invalid:
      errs_ << "Invalid probe type: " << ap.provider << std::endl;
      return INVALID;
  }

  __builtin_unreachable();
}

AttachPointParser::State AttachPointParser::lex_attachpoint(
    const AttachPoint &ap)
{
  std::string raw = ap.raw_input;
  std::vector<std::string> ret;
  bool in_quotes = false;
  std::string argument;

  for (size_t idx = 0; idx < raw.size(); ++idx) {
    if (raw[idx] == ':' && !in_quotes) {
      parts_.emplace_back(std::move(argument));
      // The standard says an std::string in moved-from state is in
      // valid but unspecified state, so clear() to be safe
      argument.clear();
    } else if (raw[idx] == '"')
      in_quotes = !in_quotes;
    // Handle escaped characters in a string
    else if (in_quotes && raw[idx] == '\\' && (idx + 1 < raw.size())) {
      argument += raw[idx + 1];
      ++idx;
    } else if (!in_quotes && raw[idx] == '$') {
      size_t i = idx + 1;
      size_t len = 0;
      while (i < raw.size() && std::isdigit(raw[i])) {
        if (len == 0 && raw[i] == '0') {
          break;
        }
        len++;
        i++;
      }

      std::string param_idx_str;

      if (len == 0 && (idx + 1) < raw.size()) {
        param_idx_str = raw.substr(idx + 1, 1);
        errs_
            << "invalid trailing character for positional param: "
            << param_idx_str
            << ". Try quoting this entire part if this is intentional e.g. \"$"
            << param_idx_str << "\".";
        return State::INVALID;
      }

      param_idx_str = raw.substr(idx + 1, len);
      auto param_idx = util::to_uint(param_idx_str, 10);
      if (!param_idx) {
        errs_ << "positional parameter is not valid: " << param_idx.takeError()
              << std::endl;
        return State::INVALID;
      }

      // Expand the positional param in-place and decrement idx so that the next
      // iteration takes the first char of the expansion
      raw = raw.substr(0, idx) + bpftrace_.get_param(*param_idx) +
            raw.substr(i);
      idx--;
    } else
      argument += raw[idx];
  }

  // Add final argument
  //
  // There will always be text in `argument` unless the AP definition
  // ended in a ':' which we will treat as an empty argument.
  parts_.emplace_back(std::move(argument));

  return State::OK;
}

AttachPointParser::State AttachPointParser::special_parser()
{
  // Can only have reached here if provider is `begin` or `end` or `self`
  assert(ap_->provider == "begin" || ap_->provider == "end" ||
         ap_->provider == "self");

  if (ap_->provider == "begin" || ap_->provider == "end") {
    if (parts_.size() == 2 && parts_[1] == "*")
      parts_.pop_back();
    if (parts_.size() != 1) {
      return argument_count_error(0);
    }
  } else if (ap_->provider == "self") {
    if (parts_.size() != 3) {
      return argument_count_error(2);
    }
    ap_->target = parts_[1];
    ap_->func = parts_[2];
  }

  return OK;
}

AttachPointParser::State AttachPointParser::test_parser()
{
  // Can only have reached here if provider is `test`
  assert(ap_->provider == "test");
  if (parts_.size() != 2) {
    return argument_count_error(1);
  }

  ap_->target = parts_[1];
  return OK;
}

AttachPointParser::State AttachPointParser::benchmark_parser()
{
  // Can only have reached here if provider is `bench`
  assert(ap_->provider == "bench");
  if (parts_.size() != 2) {
    return argument_count_error(1);
  }

  ap_->target = parts_[1];
  return OK;
}

AttachPointParser::State AttachPointParser::kprobe_parser(bool allow_offset)
{
  auto num_parts = parts_.size();
  if (num_parts != 2 && num_parts != 3) {
    if (ap_->ignore_invalid)
      return SKIP;

    return argument_count_error(1, 2);
  }

  auto func_idx = 1;
  if (num_parts == 3) {
    ap_->target = parts_[1];
    func_idx = 2;
  }

  // Handle kprobe:func+0x100 case
  auto plus_count = std::count(parts_[func_idx].cbegin(),
                               parts_[func_idx].cend(),
                               '+');
  if (plus_count) {
    if (!allow_offset) {
      errs_ << "Offset not allowed" << std::endl;
      return INVALID;
    }

    if (plus_count != 1) {
      errs_ << "Cannot take more than one offset" << std::endl;
      return INVALID;
    }

    auto offset_parts = util::split_string(parts_[func_idx], '+', true);
    if (offset_parts.size() != 2) {
      errs_ << "Invalid offset" << std::endl;
      return INVALID;
    }

    ap_->func = offset_parts[0];

    auto res = util::to_uint(offset_parts[1]);
    if (!res) {
      errs_ << "Invalid offset: " << res.takeError() << std::endl;
      return INVALID;
    }
    ap_->func_offset = *res;
  }
  // Default case (eg kprobe:func)
  else {
    ap_->func = parts_[func_idx];
  }

  return OK;
}

AttachPointParser::State AttachPointParser::kretprobe_parser()
{
  return kprobe_parser(false);
}

AttachPointParser::State AttachPointParser::uprobe_parser(bool allow_offset,
                                                          bool allow_abs_addr)
{
  const auto pid = bpftrace_.pid();
  if (pid.has_value() &&
      (parts_.size() == 2 ||
       (parts_.size() == 3 && is_supported_lang(parts_[1])))) {
    // For PID, the target may be skipped
    parts_.insert(parts_.begin() + 1, "");

    auto target = util::get_pid_exe(*pid);
    parts_[1] = target ? util::path_for_pid_mountns(*pid, *target) : "";
  }

  if (parts_.size() != 3 && parts_.size() != 4) {
    if (ap_->ignore_invalid)
      return SKIP;

    return argument_count_error(2, 3);
  }

  if (parts_.size() == 4)
    ap_->lang = parts_[2];

  ap_->target = "";

  if (!util::has_wildcard(parts_[1]) && parts_[1].starts_with("lib")) {
    // Automatic resolution of shared library paths.
    // If the target has form "libXXX" then we use BCC to find the correct path
    // to the given library as it may differ across systems.
    auto libname = parts_[1].substr(3);
    auto *lib_path = bcc_procutils_which_so(libname.c_str(),
                                            bpftrace_.pid().value_or(0));
    if (lib_path) {
      ap_->target = lib_path;
      ::free(lib_path);
    }
  }

  if (ap_->target.empty()) {
    ap_->target = parts_[1];
  }

  const std::string &func = parts_.back();
  // Handle uprobe:/lib/asdf:func+0x100 case
  auto plus_count = std::count(func.cbegin(), func.cend(), '+');
  if (plus_count) {
    if (!allow_offset) {
      errs_ << "Offset not allowed" << std::endl;
      return INVALID;
    }

    if (plus_count != 1) {
      errs_ << "Cannot take more than one offset" << std::endl;
      return INVALID;
    }

    auto offset_parts = util::split_string(func, '+', true);
    if (offset_parts.size() != 2) {
      errs_ << "Invalid offset" << std::endl;
      return INVALID;
    }

    ap_->func = offset_parts[0];
    auto res = util::to_uint(offset_parts[1]);
    if (!res) {
      errs_ << "Invalid offset: " << res.takeError() << std::endl;
      return INVALID;
    }
    ap_->func_offset = *res;
  }
  // Default case (eg uprobe:[addr][func])
  else {
    if (allow_abs_addr) {
      auto res = util::to_uint(func);
      if (res) {
        if (util::has_wildcard(ap_->target)) {
          errs_ << "Cannot use wildcards with absolute address" << std::endl;
          return INVALID;
        }
        ap_->address = *res;
      } else {
        ap_->address = 0;
        ap_->func = func;
      }
    } else
      ap_->func = func;
  }

  return OK;
}

AttachPointParser::State AttachPointParser::uretprobe_parser()
{
  return uprobe_parser(false);
}

AttachPointParser::State AttachPointParser::usdt_parser()
{
  if (bpftrace_.pid().has_value()) {
    // For PID, the target can be skipped
    if (parts_.size() == 2) {
      parts_.push_back(parts_[1]);
      parts_[1] = "";
    }
  }
  if (parts_.size() != 3 && parts_.size() != 4) {
    if (ap_->ignore_invalid)
      return SKIP;

    return argument_count_error(2, 3);
  }

  if (parts_.size() == 3) {
    ap_->target = parts_[1];
    ap_->func = parts_[2];
  } else {
    ap_->target = parts_[1];
    ap_->ns = parts_[2];
    ap_->func = parts_[3];
  }

  return OK;
}

AttachPointParser::State AttachPointParser::tracepoint_parser()
{
  // Help with `bpftrace -l 'tracepoint:*foo*'` listing -- wildcard the
  // tracepoint category b/c user is most likely to be looking for the event
  // name
  if (parts_.size() == 2 && util::has_wildcard(parts_.at(1)))
    parts_.insert(parts_.begin() + 1, "*");

  if (parts_.size() != 3) {
    if (ap_->ignore_invalid)
      return SKIP;

    return argument_count_error(2);
  }

  ap_->target = parts_[1];
  ap_->func = parts_[2];

  return OK;
}

// Used for both profile and interval probes
AttachPointParser::State AttachPointParser::frequency_parser()
{
  if (parts_.size() == 2) {
    if (util::has_wildcard(parts_[1])) {
      // Wildcards are allowed for listing
      ap_->target = parts_[1];
      ap_->freq = 0;
      return OK;
    }

    auto res = util::to_uint(parts_[1]);
    if (!res) {
      errs_ << "Invalid rate of " << ap_->provider
            << " probe: " << res.takeError() << std::endl;
      return INVALID;
    }
    if (*res < 1000) {
      errs_ << "Invalid rate of " << ap_->provider
            << " probe. Minimum is 1000 or 1us. Found: " << *res
            << " nanoseconds" << std::endl;
      return INVALID;
    }
    ap_->target = "us";
    // res is in nanoseconds
    ap_->freq = (*res / 1000);
    return OK;
  }

  if (parts_.size() != 3) {
    return argument_count_error(1, 2);
  }

  ap_->target = parts_[1];
  auto res = util::to_uint(parts_[2]);
  if (!res) {
    errs_ << "Invalid rate of " << ap_->provider
          << " probe: " << res.takeError() << std::endl;
    return INVALID;
  }

  ap_->freq = *res;
  return OK;
}

AttachPointParser::State AttachPointParser::profile_parser()
{
  return frequency_parser();
}

AttachPointParser::State AttachPointParser::interval_parser()
{
  return frequency_parser();
}

AttachPointParser::State AttachPointParser::software_parser()
{
  if (parts_.size() != 2 && parts_.size() != 3) {
    if (ap_->ignore_invalid)
      return SKIP;

    return argument_count_error(1, 2);
  }

  ap_->target = parts_[1];

  if (parts_.size() == 3 && parts_[2] != "*") {
    auto res = util::to_uint(parts_[2]);
    if (!res) {
      errs_ << "Invalid count for " << ap_->provider
            << " probe: " << res.takeError() << std::endl;
      return INVALID;
    }
    ap_->freq = *res;
  }

  return OK;
}

AttachPointParser::State AttachPointParser::hardware_parser()
{
  if (parts_.size() != 2 && parts_.size() != 3) {
    if (ap_->ignore_invalid)
      return SKIP;

    return argument_count_error(1, 2);
  }

  ap_->target = parts_[1];

  if (parts_.size() == 3 && parts_[2] != "*") {
    auto res = util::to_uint(parts_[2]);
    if (!res) {
      errs_ << "Invalid count for " << ap_->provider
            << " probe: " << res.takeError() << std::endl;
      return INVALID;
    }
    ap_->freq = *res;
  }

  return OK;
}

AttachPointParser::State AttachPointParser::watchpoint_parser()
{
  if (parts_.size() != 4) {
    return argument_count_error(3);
  }

  auto parsed = util::to_uint(parts_[1]);
  if (!parsed) {
    errs_ << "Invalid function/address argument: " << parsed.takeError()
          << std::endl;
    return INVALID;
  }
  ap_->address = *parsed;

  auto len_parsed = util::to_uint(parts_[2]);
  if (!len_parsed) {
    errs_ << "Invalid length argument: " << len_parsed.takeError() << std::endl;
    return INVALID;
  }
  ap_->len = *len_parsed;

  // An earlier pass will ensure a cmd/pid was provided
  ap_->target = bpftrace_.get_watchpoint_binary_path().value_or("");

  ap_->mode = parts_[3];

  return OK;
}

AttachPointParser::State AttachPointParser::fentry_parser()
{
  // fentry[:module]:function
  // fentry:bpf:[:prog_id]:prog_name
  if (parts_.size() != 2 && parts_.size() != 3 && parts_.size() != 4) {
    if (ap_->ignore_invalid)
      return SKIP;

    return argument_count_error(1, 3);
  }

  if (parts_[1] == "bpf") {
    ap_->target = parts_[1];
    if (parts_.size() == 2) {
      errs_ << "the 'bpf' variant of this probe requires a bpf program name "
               "and optional bpf program id";
      return INVALID;
    } else if (parts_.size() == 3) {
      ap_->func = parts_[2];
    } else {
      ap_->func = parts_[3];
      if (parts_[2] != "*") {
        auto uint_res = util::to_uint(parts_[2]);
        if (!uint_res) {
          errs_ << "bpf program id must be a number or '*'";
          return INVALID;
        }
        ap_->bpf_prog_id = *uint_res;
      }
    }
    return OK;
  }

  if (parts_.size() == 4) {
    errs_ << "Only the 'bpf' variant of this probe supports 4 arguments";
    return INVALID;
  }

  if (parts_.size() == 3) {
    ap_->target = parts_[1];
    ap_->func = parts_[2];
  } else {
    ap_->func = parts_[1];
    if (!util::has_wildcard(ap_->func)) {
      auto func_modules = func_info_state_.kernel_info().get_func_modules(
          ap_->func);
      if (func_modules.size() == 1)
        ap_->target = *func_modules.begin();
      else if (func_modules.size() > 1) {
        // Attaching to multiple functions of the same name is currently
        // broken, ask the user to specify a module explicitly.
        errs_ << "ambiguous attach point, please specify module containing "
                 "the function \'"
              << ap_->func << "\'";
        return INVALID;
      }
    } else // leave the module empty for now
      ap_->target = "*";
  }

  return OK;
}

AttachPointParser::State AttachPointParser::iter_parser()
{
  if (parts_.size() != 2 && parts_.size() != 3) {
    if (ap_->ignore_invalid)
      return SKIP;

    errs_ << ap_->provider << " probe type takes 2 arguments (1 optional)"
          << std::endl;
    return INVALID;
  }

  if (has_iter_ap_) {
    errs_ << ap_->provider << " probe only supports one attach point."
          << std::endl;
    return INVALID;
  }

  if (util::has_wildcard(parts_[1]) ||
      (parts_.size() == 3 && util::has_wildcard(parts_[2]))) {
    errs_ << ap_->provider << " probe type does not support wildcards";
    return INVALID;
  }

  ap_->func = parts_[1];

  if (parts_.size() == 3)
    ap_->pin = parts_[2];

  has_iter_ap_ = true;
  return OK;
}

AttachPointParser::State AttachPointParser::raw_tracepoint_parser()
{
  if (parts_.size() != 2 && parts_.size() != 3) {
    if (ap_->ignore_invalid)
      return SKIP;

    return argument_count_error(2, 1);
  }

  if (parts_.size() == 3) {
    ap_->target = parts_[1];
    ap_->func = parts_[2];
  } else {
    // This is to maintain backwards compatibility with older scripts
    // that couldn't include a target for a raw tracepoint.
    ap_->target = "*";
    ap_->func = parts_[1];
  }

  return OK;
}

Pass CreateParseAttachpointsPass()
{
  return Pass::create(
      "parse-attachpoints",
      [](ASTContext &ast, BPFtrace &b, FunctionInfo &func_info) {
        AttachPointParser ap_parser(ast, b, func_info);
        ap_parser.parse();
      });
}

Pass CreateCheckAttachpointsPass()
{
  return Pass::create(
      "check-attachpoints",
      [](ASTContext &ast, BPFtrace &b, FunctionInfo &func_info) {
        AttachPointChecker ap_checker(b, func_info);
        ap_checker.visit(*ast.root);
      });
}

} // namespace bpftrace::ast
