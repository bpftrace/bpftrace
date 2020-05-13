#include "attachpoint_parser.h"

#include <algorithm>
#include <exception>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include "types.h"

namespace bpftrace {
namespace ast {

AttachPointParser::AttachPointParser(Program *root,
                                     BPFtrace &bpftrace,
                                     std::ostream &sink)
    : root_(root), bpftrace_(bpftrace), sink_(sink)
{
}

int AttachPointParser::parse()
{
  if (!root_)
    return 1;

  uint32_t failed = 0;
  for (Probe *probe : *(root_->probes))
  {
    for (AttachPoint *ap : *(probe->attach_points))
    {
      if (parse_attachpoint(*ap))
      {
        ++failed;
        bpftrace_.error(sink_, ap->loc, errs_.str());
        errs_.str({}); // clear buffer
      }
    }
  }

  return failed;
}

int AttachPointParser::parse_attachpoint(AttachPoint &ap)
{
  ap_ = &ap;

  parts_.clear();
  if (lex_attachpoint(*ap_))
    return 1;

  if (parts_.empty())
  {
    errs_ << "Invalid attachpoint definition" << std::endl;
    return 1;
  }

  ap_->provider = probetypeName(parts_.front());

  switch (probetype(parts_.front()))
  {
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
    case ProbeType::kfunc:
    case ProbeType::kretfunc:
      return kfunc_parser();
    default:
      errs_ << "Unrecognized probe type: " << ap_->provider << std::endl;
      return 1;
  }

  return 0;
}

int AttachPointParser::lex_attachpoint(const AttachPoint &ap)
{
  const auto &raw = ap.raw_input;
  std::vector<std::string> ret;
  bool in_quotes = false;
  std::string argument;

  for (size_t idx = 0; idx < raw.size(); ++idx)
  {
    if (raw[idx] == ':' && !in_quotes)
    {
      parts_.emplace_back(std::move(argument));
      // The standard says an std::string in moved-from state is in
      // valid but unspecified state, so clear() to be safe
      argument.clear();
    }
    else if (raw[idx] == '"')
      in_quotes = !in_quotes;
    // Handle escaped characters in a string
    else if (in_quotes && raw[idx] == '\\' && (idx + 1 < raw.size()))
    {
      argument += raw[idx + 1];
      ++idx;
    }
    else if (!in_quotes && raw[idx] == '$')
    {
      // There's an assumption that the positional paramter is well
      // formed. ie we are not expecting a bare `$` or `$nonint`. The
      // bison parser should have guaranteed this.
      size_t i = idx + 1;
      size_t len = 0;
      while (i < raw.size() && (raw[i] != '"' && raw[i] != ':'))
      {
        len++;
        i++;
      }

      std::string param_idx_str = raw.substr(idx + 1, len);
      size_t pos, param_idx;
      param_idx = std::stoll(param_idx_str, &pos, 0);

      if (pos != param_idx_str.size())
      {
        errs_
            << "Found trailing text '" << param_idx_str.substr(pos)
            << "' in positional parameter index. Try quoting the trailing text."
            << std::endl;
        return 1;
      }

      argument += bpftrace_.get_param(param_idx, true);
      // NB the for loop will then do idx++ so while we consumed
      // (len + 1) characters, we only increment by (len).
      idx += len;
    }
    else
      argument += raw[idx];
  }

  // Add final argument
  //
  // There will always be text in `argument` unless the AP definition
  // ended in a ':' which we will treat as an empty argument.
  parts_.emplace_back(std::move(argument));

  return 0;
}

int AttachPointParser::kprobe_parser(bool allow_offset)
{
  if (parts_.size() != 2)
  {
    errs_ << ap_->provider << " probe type requires 1 argument" << std::endl;
    return 1;
  }

  // Handle kprobe:func+0x100 case
  auto plus_count = std::count(parts_[1].cbegin(), parts_[1].cend(), '+');
  if (plus_count)
  {
    if (!allow_offset)
    {
      errs_ << "Offset not allowed" << std::endl;
      return 1;
    }

    if (plus_count != 1)
    {
      errs_ << "Cannot take more than one offset" << std::endl;
      return 1;
    }

    auto offset_parts = split_string(parts_[1], '+', true);
    if (offset_parts.size() != 2)
    {
      errs_ << "Invalid offset" << std::endl;
      return 1;
    }

    ap_->func = offset_parts[0];

    try
    {
      std::size_t idx;
      ap_->func_offset = std::stoll(offset_parts[1], &idx, 0);

      if (idx != offset_parts[1].size())
      {
        errs_ << "Found trailing non-numeric characters: " << offset_parts[1]
              << std::endl;
        return 1;
      }
    }
    catch (const std::exception &ex)
    {
      errs_ << "Failed to parse '" << offset_parts[1] << "': " << ex.what()
            << std::endl;
      return 1;
    }
  }
  // Default case (eg kprobe:func)
  else
  {
    ap_->func = parts_[1];
  }

  if (ap_->func.find('*') != std::string::npos)
    ap_->need_expansion = true;

  return 0;
}

int AttachPointParser::kretprobe_parser()
{
  return kprobe_parser(false);
}

int AttachPointParser::uprobe_parser(bool allow_offset, bool allow_abs_addr)
{
  // Handle special probes implemented as uprobes
  if (ap_->provider == "BEGIN" || ap_->provider == "END")
  {
    if (parts_.size() != 1)
    {
      errs_ << ap_->provider << " probe type requires 0 arguments" << std::endl;
      return 1;
    }

    return 0;
  }

  // Now handle regular uprobes
  if (parts_.size() != 3)
  {
    errs_ << ap_->provider << " probe type requires 2 arguments" << std::endl;
    return 1;
  }

  ap_->target = parts_[1];

  // Handle uprobe:/lib/asdf:func+0x100 case
  auto plus_count = std::count(parts_[2].cbegin(), parts_[2].cend(), '+');
  if (plus_count)
  {
    if (!allow_offset)
    {
      errs_ << "Offset not allowed" << std::endl;
      return 1;
    }

    if (plus_count != 1)
    {
      errs_ << "Cannot take more than one offset" << std::endl;
      return 1;
    }

    auto offset_parts = split_string(parts_[2], '+', true);
    if (offset_parts.size() != 2)
    {
      errs_ << "Invalid offset" << std::endl;
      return 1;
    }

    ap_->func = offset_parts[0];

    try
    {
      std::size_t idx;
      ap_->func_offset = std::stoll(offset_parts[1], &idx, 0);

      if (idx != offset_parts[1].size())
      {
        errs_ << "Found trailing non-numeric characters: " << offset_parts[1]
              << std::endl;
        return 1;
      }
    }
    catch (const std::exception &ex)
    {
      errs_ << "Failed to parse '" << offset_parts[1] << "': " << ex.what()
            << std::endl;
      return 1;
    }
  }
  // Default case (eg uprobe:[addr][func])
  else
  {
    if (allow_abs_addr)
    {
      // First try to parse as addr. If that fails, go with symbol name.
      try
      {
        std::size_t idx;
        ap_->address = std::stoll(parts_[2], &idx, 0);

        // If there are trailing non-numeric characters, we treat the argument
        // as a string symbol. This exception will immediately be caught.
        if (idx != parts_[2].size())
        {
          ap_->address = 0;
          throw std::runtime_error("use string version");
        }
      }
      catch (const std::exception &ex)
      {
        ap_->func = parts_[2];
      }
    }
    else
      ap_->func = parts_[2];
  }

  if (ap_->target.find('*') != std::string::npos ||
      ap_->func.find('*') != std::string::npos)
    ap_->need_expansion = true;

  return 0;
}

int AttachPointParser::uretprobe_parser()
{
  return uprobe_parser(false);
}

int AttachPointParser::usdt_parser()
{
  if (parts_.size() != 3 && parts_.size() != 4)
  {
    errs_ << ap_->provider << " probe type requires 2 or 3 arguments"
          << std::endl;
    return 1;
  }

  if (parts_.size() == 3)
  {
    ap_->target = parts_[1];
    ap_->func = parts_[2];
  }
  else
  {
    ap_->target = parts_[1];
    ap_->ns = parts_[2];
    ap_->func = parts_[3];
  }

  if (ap_->target.find('*') != std::string::npos ||
      ap_->ns.find('*') != std::string::npos ||
      ap_->func.find('*') != std::string::npos)
    ap_->need_expansion = true;

  return 0;
}

int AttachPointParser::tracepoint_parser()
{
  if (parts_.size() != 3)
  {
    errs_ << ap_->provider << " probe type requires 2 arguments" << std::endl;
    return 1;
  }

  ap_->target = parts_[1];
  ap_->func = parts_[2];

  if (ap_->target.find('*') != std::string::npos ||
      ap_->func.find('*') != std::string::npos)
    ap_->need_expansion = true;

  return 0;
}

int AttachPointParser::profile_parser()
{
  if (parts_.size() != 3)
  {
    errs_ << ap_->provider << " probe type requires 2 arguments" << std::endl;
    return 1;
  }

  ap_->target = parts_[1];

  try
  {
    std::size_t idx;
    ap_->freq = std::stoi(parts_[2], &idx, 0);

    if (idx != parts_[2].size())
    {
      errs_ << "Found trailing non-numeric characters: " << parts_[2]
            << std::endl;
      return 1;
    }
  }
  catch (const std::exception &ex)
  {
    errs_ << "Failed to parse '" << parts_[2] << "': " << ex.what()
          << std::endl;
    return 1;
  }

  return 0;
}

int AttachPointParser::interval_parser()
{
  if (parts_.size() != 3)
  {
    errs_ << ap_->provider << " probe type requires 2 arguments" << std::endl;
    return 1;
  }

  ap_->target = parts_[1];

  try
  {
    std::size_t idx;
    ap_->freq = std::stoi(parts_[2], &idx, 0);

    if (idx != parts_[2].size())
    {
      errs_ << "Found trailing non-numeric characters: " << parts_[2]
            << std::endl;
      return 1;
    }
  }
  catch (const std::exception &ex)
  {
    errs_ << "Failed to parse '" << parts_[2] << "': " << ex.what()
          << std::endl;
    return 1;
  }

  return 0;
}

int AttachPointParser::software_parser()
{
  if (parts_.size() != 2 && parts_.size() != 3)
  {
    errs_ << ap_->provider << " probe type requires 1 or 2 arguments"
          << std::endl;
    return 1;
  }

  ap_->target = parts_[1];

  if (parts_.size() == 3)
  {
    try
    {
      std::size_t idx;
      ap_->freq = std::stoi(parts_[2], &idx, 0);

      if (idx != parts_[2].size())
      {
        errs_ << "Found trailing non-numeric characters: " << parts_[2]
              << std::endl;
        return 1;
      }
    }
    catch (const std::exception &ex)
    {
      errs_ << "Failed to parse '" << parts_[2] << "': " << ex.what()
            << std::endl;
      return 1;
    }
  }

  return 0;
}

int AttachPointParser::hardware_parser()
{
  if (parts_.size() != 2 && parts_.size() != 3)
  {
    errs_ << ap_->provider << " probe type requires 1 or 2 arguments"
          << std::endl;
    return 1;
  }

  ap_->target = parts_[1];

  if (parts_.size() == 3)
  {
    try
    {
      std::size_t idx;
      ap_->freq = std::stoi(parts_[2], &idx, 0);

      if (idx != parts_[2].size())
      {
        errs_ << "Found trailing non-numeric characters: " << parts_[2]
              << std::endl;
        return 1;
      }
    }
    catch (const std::exception &ex)
    {
      errs_ << "Failed to parse '" << parts_[2] << "': " << ex.what()
            << std::endl;
      return 1;
    }
  }

  return 0;
}

int AttachPointParser::watchpoint_parser()
{
  if (parts_.size() != 5)
  {
    errs_ << ap_->provider << " probe type requires 4 arguments" << std::endl;
    return 1;
  }

  try
  {
    std::size_t idx;
    ap_->address = std::stoull(parts_[2], &idx, 0);

    if (idx != parts_[2].size())
    {
      errs_ << "Found trailing non-numeric characters: " << parts_[2]
            << std::endl;
      return 1;
    }
  }
  catch (const std::exception &ex)
  {
    errs_ << "Failed to parse '" << parts_[2] << "': " << ex.what()
          << std::endl;
    return 1;
  }

  try
  {
    std::size_t idx;
    ap_->len = std::stoull(parts_[3], &idx, 0);

    if (idx != parts_[3].size())
    {
      errs_ << "Found trailing non-numeric characters: " << parts_[3]
            << std::endl;
      return 1;
    }
  }
  catch (const std::exception &ex)
  {
    errs_ << "Failed to parse '" << parts_[3] << "': " << ex.what()
          << std::endl;
    return 1;
  }

  ap_->mode = parts_[4];

  return 0;
}

int AttachPointParser::kfunc_parser()
{
  if (parts_.size() != 2)
  {
    errs_ << ap_->provider << " probe type requires 1 argument" << std::endl;
    return 1;
  }

  if (parts_[1].find('*') != std::string::npos)
  {
    errs_ << "wildcard expansion is not supported for kfunc/kretfunc probes" << std::endl;
    return 1;
  }

  ap_->func = parts_[1];
  return 0;
}

} // namespace ast
} // namespace bpftrace
