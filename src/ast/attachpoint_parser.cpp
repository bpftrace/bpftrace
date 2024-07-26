#include "ast/attachpoint_parser.h"

#include "ast.h"
#include "ast/int_parser.h"
#include "log.h"
#include "types.h"
#include <algorithm>
#include <bcc/bcc_proc.h>
#include <exception>
#include <functional>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

namespace bpftrace {
namespace ast {

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

std::optional<uint64_t> AttachPointParser::stoull(const std::string &str)
{
  try {
    return int_parser::to_uint(str, 0);
  } catch (const std::exception &e) {
    errs_ << e.what() << std::endl;
    return std::nullopt;
  }
}

std::optional<int64_t> AttachPointParser::stoll(const std::string &str)
{
  try {
    return int_parser::to_int(str, 0);
  } catch (const std::exception &e) {
    errs_ << e.what() << std::endl;
    return std::nullopt;
  }
}

AttachPointParser::AttachPointParser(ASTContext &ctx,
                                     BPFtrace &bpftrace,
                                     std::ostream &sink,
                                     bool listing)
    : ctx_(ctx), bpftrace_(bpftrace), sink_(sink), listing_(listing)
{
}

int AttachPointParser::parse()
{
  if (!ctx_.root)
    return 1;

  uint32_t failed = 0;
  for (Probe *probe : ctx_.root->probes) {
    for (size_t i = 0; i < probe->attach_points.size(); ++i) {
      auto ap_ptr = probe->attach_points[i];
      auto &ap = *ap_ptr;
      new_attach_points.clear();

      State s = parse_attachpoint(ap);
      if (s == INVALID) {
        ++failed;
        LOG(ERROR, ap.loc, sink_) << errs_.str();
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

    auto new_end = std::remove_if(probe->attach_points.begin(),
                                  probe->attach_points.end(),
                                  [](const AttachPoint *ap) {
                                    return ap->provider.empty();
                                  });
    probe->attach_points.erase(new_end, probe->attach_points.end());

    if (probe->attach_points.empty()) {
      LOG(ERROR, probe->loc, sink_) << "No attach points for probe";
      failed++;
    }
  }

  return failed;
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

  if (parts_.front().empty()) {
    // Do not fail on empty attach point, could be just a trailing comma
    ap_->provider = "";
    return OK;
  }

  std::set<std::string> probe_types;
  if (has_wildcard(parts_.front())) {
    // Single argument listing looks at all relevant probe types
    std::string probetype_query = (parts_.size() == 1) ? "*" : parts_.front();

    // Probe type expansion
    // If PID is specified or the second part of the attach point is a path
    // (contains '/'), use userspace probe types.
    // Otherwise, use kernel probe types.
    if (bpftrace_.pid() > 0 ||
        (parts_.size() >= 2 && parts_[1].find('/') != std::string::npos)) {
      probe_types = bpftrace_.probe_matcher_->expand_probetype_userspace(
          probetype_query);
    } else {
      probe_types = bpftrace_.probe_matcher_->expand_probetype_kernel(
          probetype_query);
    }
  } else
    probe_types = { parts_.front() };

  if (probe_types.empty()) {
    if (has_wildcard(parts_.front()))
      errs_ << "No probe type matched for " << parts_.front() << std::endl;
    else
      errs_ << "Invalid probe type: " << parts_.front() << std::endl;
    return INVALID;
  } else if (probe_types.size() > 1) {
    // If the probe type string matches more than 1 probe, create a new set of
    // attach points (one for every match) that will replace the original one.
    for (const auto &probe_type : probe_types) {
      std::string raw_input = ap.raw_input;
      if (parts_.size() > 1)
        erase_prefix(raw_input);
      raw_input = probe_type + ":" + raw_input;
      // New attach points have ignore_invalid set to true - probe types for
      // which raw_input has invalid number of parts will be ignored (instead
      // of throwing an error)
      new_attach_points.push_back(ctx_.make_node<AttachPoint>(raw_input, true));
    }
    return NEW_APS;
  }

  ap.provider = expand_probe_name(*probe_types.begin());

  switch (probetype(ap.provider)) {
    case ProbeType::special:
      return special_parser();
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
    case ProbeType::asyncwatchpoint:
      return watchpoint_parser(true);
    case ProbeType::kfunc:
    case ProbeType::kretfunc:
      return kfunc_parser();
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
      // There's an assumption that the positional parameter is well
      // formed. ie we are not expecting a bare `$` or `$nonint`. The
      // bison parser should have guaranteed this.
      size_t i = idx + 1;
      size_t len = 0;
      while (i < raw.size() && (raw[i] != '"' && raw[i] != ':')) {
        len++;
        i++;
      }

      std::string param_idx_str = raw.substr(idx + 1, len);
      size_t pos, param_idx;
      param_idx = std::stoll(param_idx_str, &pos, 0);

      if (pos != param_idx_str.size()) {
        errs_
            << "Found trailing text '" << param_idx_str.substr(pos)
            << "' in positional parameter index. Try quoting the trailing text."
            << std::endl;
        return State::INVALID;
      }

      // Expand the positional param in-place and decrement idx so that the next
      // iteration takes the first char of the expansion
      raw = raw.substr(0, idx) + bpftrace_.get_param(param_idx, true) +
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
  // Can only have reached here if provider is `BEGIN` or `END`
  assert(ap_->provider == "BEGIN" || ap_->provider == "END");

  if (parts_.size() == 2 && parts_[1] == "*")
    parts_.pop_back();
  if (parts_.size() != 1) {
    return argument_count_error(0);
  }

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

    auto offset_parts = split_string(parts_[func_idx], '+', true);
    if (offset_parts.size() != 2) {
      errs_ << "Invalid offset" << std::endl;
      return INVALID;
    }

    ap_->func = offset_parts[0];

    auto res = stoll(offset_parts[1]);
    if (!res) {
      errs_ << "Invalid offset" << std::endl;
      return INVALID;
    }
    ap_->func_offset = *res;
  }
  // Default case (eg kprobe:func)
  else {
    ap_->func = parts_[func_idx];
  }

  // kprobe_multi does not support the "module:function" syntax so in case
  // a module is specified, always use full expansion
  if (has_wildcard(ap_->target))
    ap_->expansion = ExpansionType::FULL;
  else if (has_wildcard(ap_->func)) {
    if (ap_->target.empty() && bpftrace_.feature_->has_kprobe_multi()) {
      ap_->expansion = ExpansionType::MULTI;
    } else {
      ap_->expansion = ExpansionType::FULL;
    }
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
  if (bpftrace_.pid() > 0 &&
      (parts_.size() == 2 ||
       (parts_.size() == 3 && is_supported_lang(parts_[1])))) {
    // For PID, the target may be skipped
    if (parts_.size() == 2)
      parts_.insert(parts_.begin() + 1, "");

    auto target = get_pid_exe(bpftrace_.pid());
    parts_[1] = path_for_pid_mountns(bpftrace_.pid(), target);
  }

  if (parts_.size() != 3 && parts_.size() != 4) {
    if (ap_->ignore_invalid)
      return SKIP;

    return argument_count_error(2, 3);
  }

  if (parts_.size() == 4)
    ap_->lang = parts_[2];

  ap_->target = "";

  if (!has_wildcard(parts_[1]) && parts_[1].find("lib") == 0) {
    // Automatic resolution of shared library paths.
    // If the target has form "libXXX" then we use BCC to find the correct path
    // to the given library as it may differ across systems.
    auto libname = parts_[1].substr(3);
    const char *lib_path = bcc_procutils_which_so(libname.c_str(),
                                                  bpftrace_.pid());
    if (lib_path)
      ap_->target = lib_path;
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

    auto offset_parts = split_string(func, '+', true);
    if (offset_parts.size() != 2) {
      errs_ << "Invalid offset" << std::endl;
      return INVALID;
    }

    ap_->func = offset_parts[0];

    auto res = stoll(offset_parts[1]);
    if (!res) {
      errs_ << "Invalid offset" << std::endl;
      return INVALID;
    }
    ap_->func_offset = *res;
  }
  // Default case (eg uprobe:[addr][func])
  else {
    if (allow_abs_addr) {
      auto res = stoll(func);
      if (res) {
        if (has_wildcard(ap_->target)) {
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

  // As the C++ language supports function overload, a given function name
  // (without parameters) could have multiple matches even when no
  // wildcards are used.
  if (has_wildcard(ap_->func) || has_wildcard(ap_->target) ||
      ap_->lang == "cpp") {
    if (bpftrace_.feature_->has_uprobe_multi()) {
      ap_->expansion = ExpansionType::MULTI;
    } else {
      ap_->expansion = ExpansionType::FULL;
    }
  }

  return OK;
}

AttachPointParser::State AttachPointParser::uretprobe_parser()
{
  return uprobe_parser(false);
}

AttachPointParser::State AttachPointParser::usdt_parser()
{
  if (bpftrace_.pid() > 0) {
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

  // Always fully expand USDT probes as they may access args
  if (has_wildcard(ap_->target) || has_wildcard(ap_->ns) || ap_->ns.empty() ||
      has_wildcard(ap_->func) || bpftrace_.pid())
    ap_->expansion = ExpansionType::FULL;

  return OK;
}

AttachPointParser::State AttachPointParser::tracepoint_parser()
{
  // Help with `bpftrace -l 'tracepoint:*foo*'` listing -- wildcard the
  // tracepoint category b/c user is most likely to be looking for the event
  // name
  if (parts_.size() == 2 && has_wildcard(parts_.at(1)))
    parts_.insert(parts_.begin() + 1, "*");

  if (parts_.size() != 3) {
    if (ap_->ignore_invalid)
      return SKIP;

    return argument_count_error(2);
  }

  ap_->target = parts_[1];
  ap_->func = parts_[2];

  if (ap_->target.find('*') != std::string::npos ||
      ap_->func.find('*') != std::string::npos)
    ap_->expansion = ExpansionType::FULL;

  return OK;
}

AttachPointParser::State AttachPointParser::profile_parser()
{
  if (parts_.size() == 2 && has_wildcard(parts_[1])) {
    // Wildcards are allowed for listing
    ap_->target = parts_[1];
    ap_->freq = 0;
    return OK;
  }

  if (parts_.size() != 3) {
    return argument_count_error(2);
  }

  ap_->target = parts_[1];

  auto res = stoull(parts_[2]);
  if (!res) {
    errs_ << "Invalid rate of " << ap_->provider << " probe";
    return INVALID;
  }

  ap_->freq = *res;
  return OK;
}

AttachPointParser::State AttachPointParser::interval_parser()
{
  if (parts_.size() == 2 && has_wildcard(parts_[1])) {
    // Wildcards are allowed for listing
    ap_->target = parts_[1];
    ap_->freq = 0;
    return OK;
  }

  if (parts_.size() != 3) {
    return argument_count_error(2);
  }

  ap_->target = parts_[1];
  auto res = stoull(parts_[2]);
  if (!res) {
    errs_ << "Invalid rate of " << ap_->provider << " probe";
    return INVALID;
  }

  ap_->freq = *res;
  return OK;
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
    auto res = stoull(parts_[2]);
    if (!res) {
      errs_ << "Invalid count for " << ap_->provider << " probe";
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
    auto res = stoull(parts_[2]);
    if (!res) {
      errs_ << "Invalid count for " << ap_->provider << " probe";
      return INVALID;
    }
    ap_->freq = *res;
  }

  return OK;
}

AttachPointParser::State AttachPointParser::watchpoint_parser(bool async)
{
  if (parts_.size() != 4) {
    return argument_count_error(3);
  }

  if (parts_[1].find('+') == std::string::npos) {
    auto parsed = stoull(parts_[1]);
    if (!parsed) {
      errs_ << "Invalid function/address argument" << std::endl;
      return INVALID;
    }
    ap_->address = *parsed;
  } else {
    auto func_arg_parts = split_string(parts_[1], '+', true);
    if (func_arg_parts.size() != 2) {
      errs_ << "Invalid function/address argument" << std::endl;
      return INVALID;
    }

    ap_->func = func_arg_parts[0];
    if (ap_->func.find('*') != std::string::npos)
      ap_->expansion = ExpansionType::FULL;

    if (func_arg_parts[1].size() <= 3 || func_arg_parts[1].find("arg") != 0) {
      errs_ << "Invalid function argument" << std::endl;
      return INVALID;
    }

    auto parsed = stoull(func_arg_parts[1].substr(3));
    if (!parsed) {
      errs_ << "Invalid function argument" << std::endl;
      return INVALID;
    }
    ap_->address = *parsed;
  }

  auto len_parsed = stoull(parts_[2]);
  if (!len_parsed) {
    errs_ << "Invalid length argument" << std::endl;
    return INVALID;
  }
  ap_->len = *len_parsed;

  // Semantic analyser will ensure a cmd/pid was provided
  ap_->target = bpftrace_.get_watchpoint_binary_path().value_or("");

  ap_->mode = parts_[3];

  ap_->async = async;

  return OK;
}

AttachPointParser::State AttachPointParser::kfunc_parser()
{
  // kfunc[:module]:function
  if (parts_.size() != 2 && parts_.size() != 3) {
    if (ap_->ignore_invalid)
      return SKIP;

    return argument_count_error(1, 2);
  }

  if (parts_.size() == 3) {
    ap_->target = parts_[1];
    ap_->func = parts_[2];
  } else {
    ap_->func = parts_[1];
    if (ap_->func.find('*') == std::string::npos) {
      auto func_modules = bpftrace_.get_func_modules(ap_->func);
      if (func_modules.size() == 1)
        ap_->target = *func_modules.begin();
      else if (func_modules.size() > 1) {
        if (listing_)
          ap_->target = "*";
        else {
          // Attaching to multiple functions of the same name is currently
          // broken, ask the user to specify a module explicitly.
          errs_ << "ambiguous attach point, please specify module containing "
                   "the function \'"
                << ap_->func << "\'";
          return INVALID;
        }
      }
    } else // leave the module empty for now
      ap_->target = "*";
  }

  if (ap_->func.find('*') != std::string::npos ||
      ap_->target.find('*') != std::string::npos)
    ap_->expansion = ExpansionType::FULL;

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

  if (parts_[1].find('*') != std::string::npos) {
    if (listing_) {
      ap_->expansion = ExpansionType::FULL;
    } else {
      if (ap_->ignore_invalid)
        return SKIP;

      errs_ << ap_->provider << " probe type does not support wildcards"
            << std::endl;
      return INVALID;
    }
  }

  ap_->func = parts_[1];

  if (parts_.size() == 3)
    ap_->pin = parts_[2];
  return OK;
}

AttachPointParser::State AttachPointParser::raw_tracepoint_parser()
{
  if (parts_.size() != 2) {
    if (ap_->ignore_invalid)
      return SKIP;

    return argument_count_error(1);
  }

  ap_->func = parts_[1];

  if (has_wildcard(ap_->func))
    ap_->expansion = ExpansionType::FULL;

  return OK;
}

} // namespace ast
} // namespace bpftrace
