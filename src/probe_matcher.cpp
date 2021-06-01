#include <dirent.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <string>
#include <vector>

#include "bpftrace.h"
#include "log.h"
#include "probe_matcher.h"
#include "utils.h"

#include <bcc/bcc_syms.h>

#include <llvm/Demangle/Demangle.h>

#ifdef HAVE_BCC_ELF_FOREACH_SYM
#include <bcc/bcc_elf.h>
#include <linux/elf.h>
#endif

namespace bpftrace {

#ifdef HAVE_BCC_ELF_FOREACH_SYM
static int add_symbol(const char* symname,
                      uint64_t /*start*/,
                      uint64_t /*size*/,
                      void* payload)
{
  auto syms = static_cast<std::set<std::string>*>(payload);
  syms->insert(std::string(symname));
  return 0;
}
#endif

/*
 * Splits input string by '*' delimiter and return the individual parts.
 * Sets start_wildcard and end_wildcard if input starts or ends with '*'.
 */
std::vector<std::string> get_tokens(const std::string& input,
                                    bool& start_wildcard,
                                    bool& end_wildcard)
{
  if (input.empty())
    return {};

  start_wildcard = input[0] == '*';
  end_wildcard = input[input.length() - 1] == '*';

  std::vector<std::string> tokens = split_string(input, '*');
  tokens.erase(std::remove(tokens.begin(), tokens.end(), ""), tokens.end());
  return tokens;
}

/*
 * Finds all matches of search_input in the provided input stream.
 *
 * If `ignore_trailing_module` is true, will ignore trailing kernel module.
 * For example, `[ehci_hcd]` will be ignored in:
 *     ehci_disable_ASE [ehci_hcd]
 */
std::set<std::string> ProbeMatcher::get_matches_in_stream(
    const std::string& search_input,
    bool ignore_trailing_module,
    std::istream& symbol_stream,
    const char delim)
{
  bool start_wildcard, end_wildcard;
  auto tokens = get_tokens(search_input, start_wildcard, end_wildcard);

  std::string line;
  std::set<std::string> matches;
  while (std::getline(symbol_stream, line, delim))
  {
    if (ignore_trailing_module && symbol_has_module(line))
    {
      line = strip_symbol_module(line);
    }

    if (!wildcard_match(line, tokens, start_wildcard, end_wildcard))
    {
      auto fun_line = line;
      auto prefix = fun_line.find(':') != std::string::npos
                        ? erase_prefix(fun_line) + ":"
                        : "";
      if (symbol_has_cpp_mangled_signature(fun_line))
      {
        char* demangled_name = llvm::itaniumDemangle(
            fun_line.c_str(), nullptr, nullptr, nullptr);
        if (demangled_name)
        {
          if (!wildcard_match(prefix + demangled_name, tokens, true, true))
          {
            free(demangled_name);
          }
          else
          {
            free(demangled_name);
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

std::unique_ptr<std::istream> ProbeMatcher::get_iter_symbols(void) const
{
  return std::make_unique<std::istringstream>("task\ntask_file");
}

/*
 * Get matches of search_input (containing a wildcard) for a given probe_type.
 * probe_type determines where to take the candidate matches from.
 * Some probe types (e.g. uprobe) require target to be specified.
 */
std::set<std::string> ProbeMatcher::get_matches_for_probetype(
    const ProbeType& probe_type,
    const std::string& target,
    const std::string& search_input)
{
  std::unique_ptr<std::istream> symbol_stream;
  bool ignore_trailing_module = false;

  switch (probe_type)
  {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
    {
      symbol_stream = get_symbols_from_file(kprobe_path);
      ignore_trailing_module = true;
      break;
    }
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::watchpoint:
    case ProbeType::asyncwatchpoint:
    {
      symbol_stream = get_func_symbols_from_file(target);
      break;
    }
    case ProbeType::tracepoint:
    {
      symbol_stream = get_symbols_from_file(tp_avail_path);
      break;
    }
    case ProbeType::usdt:
    {
      symbol_stream = get_symbols_from_usdt(bpftrace_->pid(), target);
      break;
    }
    case ProbeType::software:
    {
      symbol_stream = get_symbols_from_list(SW_PROBE_LIST);
      break;
    }
    case ProbeType::hardware:
    {
      symbol_stream = get_symbols_from_list(HW_PROBE_LIST);
      break;
    }
    case ProbeType::kfunc:
    case ProbeType::kretfunc:
    {
      symbol_stream = bpftrace_->btf_.get_all_funcs();
      break;
    }
    case ProbeType::iter:
    {
      symbol_stream = get_iter_symbols();
      break;
    }
    default:
      return {};
  }

  if (symbol_stream)
    return get_matches_in_stream(search_input,
                                 ignore_trailing_module,
                                 *symbol_stream);
  else
    return {};
}

/*
 * Find all matches of search_input in set
 */
std::set<std::string> ProbeMatcher::get_matches_in_set(
    const std::string& search_input,
    const std::set<std::string>& set)
{
  std::string stream_in;
  // Strings in the set may contain a newline character, so we use '$'
  // as a delimiter.
  for (auto& str : set)
    stream_in.append(str + "$");

  std::istringstream stream(stream_in);
  return get_matches_in_stream(search_input, false, stream, '$');
}

std::unique_ptr<std::istream> ProbeMatcher::get_symbols_from_file(
    const std::string& path) const
{
  auto file = std::make_unique<std::ifstream>(path);
  if (file->fail())
  {
    throw std::runtime_error("Could not read symbols from " + path + ": " +
                             strerror(errno));
  }

  return file;
}

std::unique_ptr<std::istream> ProbeMatcher::get_func_symbols_from_file(
    const std::string& path) const
{
  if (path.empty())
    return std::make_unique<std::istringstream>("");

  std::vector<std::string> real_paths;
  if (path.find('*') != std::string::npos)
    real_paths = resolve_binary_path(path);
  else
    real_paths.push_back(path);
#ifdef HAVE_BCC_ELF_FOREACH_SYM
  struct bcc_symbol_option symbol_option;
  memset(&symbol_option, 0, sizeof(symbol_option));
  symbol_option.use_debug_file = 1;
  symbol_option.check_debug_file_crc = 1;
  symbol_option.use_symbol_type = (1 << STT_FUNC) | (1 << STT_GNU_IFUNC);
#endif

  std::string result;
  for (auto& real_path : real_paths)
  {
    std::set<std::string> syms;
#ifdef HAVE_BCC_ELF_FOREACH_SYM
    // Workaround: bcc_elf_foreach_sym() can return the same symbol twice if
    // it's also found in debug info (#1138), so a std::set is used here (and in
    // the add_symbol callback) to ensure that each symbol will be unique in the
    // returned string.
    int err = bcc_elf_foreach_sym(
        real_path.c_str(), add_symbol, &symbol_option, &syms);
    if (err)
    {
      LOG(WARNING) << "Could not list function symbols: " + real_path;
    }
#else
    std::string call_str = std::string("objdump -tT ") + real_path + +" | " +
                           "grep \"F .text\" | grep -oE '[^[:space:]]+$'";
    const char* call = call_str.c_str();
    std::istringstream iss(exec_system(call));
    std::copy(std::istream_iterator<std::string>(iss),
              std::istream_iterator<std::string>(),
              std::inserter(syms, syms.begin()));
#endif
    for (auto& sym : syms)
      result += real_path + ":" + sym + "\n";
  }
  return std::make_unique<std::istringstream>(result);
}

std::unique_ptr<std::istream> ProbeMatcher::get_symbols_from_usdt(
    int pid,
    const std::string& target) const
{
  std::string probes;
  usdt_probe_list usdt_probes;

  if (pid > 0)
    usdt_probes = USDTHelper::probes_for_pid(pid);
  else if (!target.empty())
  {
    std::vector<std::string> real_paths;
    if (target.find('*') != std::string::npos)
      real_paths = resolve_binary_path(target);
    else
      real_paths.push_back(target);

    for (auto& real_path : real_paths)
    {
      auto target_usdt_probes = USDTHelper::probes_for_path(real_path);
      usdt_probes.insert(usdt_probes.end(),
                         target_usdt_probes.begin(),
                         target_usdt_probes.end());
    }
  }

  for (auto const& usdt_probe : usdt_probes)
  {
    std::string path = usdt_probe.path;
    std::string provider = usdt_probe.provider;
    std::string fname = usdt_probe.name;
    probes += path + ":" + provider + ":" + fname + "\n";
  }

  return std::make_unique<std::istringstream>(probes);
}

std::unique_ptr<std::istream> ProbeMatcher::get_symbols_from_list(
    const std::vector<ProbeListItem>& probes_list) const
{
  std::string symbols;
  for (auto& probe : probes_list)
    symbols += probe.path + ":\n";
  return std::make_unique<std::istringstream>(symbols);
}

/*
 * Get list of kernel probe types for the purpose of listing.
 * Ignore return probes.
 */
std::unique_ptr<std::istream> ProbeMatcher::kernel_probe_list()
{
  std::string probes;
  for (auto& p : PROBE_LIST)
  {
    if (p.type == ProbeType::kfunc)
    {
      // kfunc must be available
      if (bpftrace_->btf_.has_data())
        probes += p.name + "\n";
    }
    else if (p.name.find("ret") == std::string::npos &&
             !is_userspace_probe(p.type) && p.type != ProbeType::interval &&
             p.type != ProbeType::profile && p.type != ProbeType::watchpoint &&
             p.type != ProbeType::asyncwatchpoint)
    {
      probes += p.name + "\n";
    }
  }

  return std::make_unique<std::istringstream>(probes);
}

/*
 * Get list of userspace probe types for the purpose of listing.
 * Ignore return probes.
 */
std::unique_ptr<std::istream> ProbeMatcher::userspace_probe_list()
{
  std::string probes;
  for (auto& p : PROBE_LIST)
  {
    if (p.name.find("ret") == std::string::npos && is_userspace_probe(p.type) &&
        p.name != "BEGIN" && p.name != "END")
      probes += p.name + "\n";
  }

  return std::make_unique<std::istringstream>(probes);
}

FuncParamLists ProbeMatcher::get_tracepoints_params(
    const std::set<std::string>& tracepoints)
{
  FuncParamLists params;
  for (auto& tracepoint : tracepoints)
  {
    auto event = tracepoint;
    auto category = erase_prefix(event);

    std::string format_file_path = tp_path + "/" + category + "/" + event +
                                   "/format";
    std::ifstream format_file(format_file_path.c_str());
    std::string line;

    if (format_file.fail())
    {
      LOG(ERROR) << "tracepoint format file not found: " << format_file_path;
      return {};
    }

    // Skip lines until the first empty line
    do
    {
      getline(format_file, line);
    } while (line.length() > 0);

    while (getline(format_file, line))
    {
      if (line.find("\tfield:") == 0)
      {
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
  FuncParamLists params;

  for (auto& iter : iters)
  {
    if (iter == "task")
    {
      params[iter].push_back("struct task_struct * task");
    }
    else if (iter == "task_file")
    {
      params[iter].push_back("struct task_struct * task");
      params[iter].push_back("int fd");
      params[iter].push_back("struct file * file");
    }
  }

  return params;
}

void ProbeMatcher::list_probes(ast::Program* prog)
{
  for (auto* probe : *prog->probes)
  {
    for (auto* ap : *probe->attach_points)
    {
      auto matches = get_matches_for_ap(*ap);
      auto probe_type = probetype(ap->provider);
      FuncParamLists param_lists;
      if (bt_verbose)
      {
        if (probe_type == ProbeType::tracepoint)
          param_lists = get_tracepoints_params(matches);
        else if (probe_type == ProbeType::kfunc ||
                 probe_type == ProbeType::kretfunc)
          param_lists = bpftrace_->btf_.get_params(matches);
        else if (probe_type == ProbeType::iter)
          param_lists = get_iters_params(matches);
      }

      for (auto& match : matches)
      {
        std::cout << probetypeName(probe_type) << ":" << match << std::endl;
        if (bt_verbose)
        {
          for (auto& param : param_lists[match])
            std::cout << "    " << param << std::endl;
        }
      }
    }
  }
}

std::set<std::string> ProbeMatcher::get_matches_for_ap(
    const ast::AttachPoint& attach_point)
{
  std::string search_input;
  switch (probetype(attach_point.provider))
  {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
    case ProbeType::kfunc:
    case ProbeType::kretfunc:
    case ProbeType::iter:
    {
      search_input = attach_point.func;
      break;
    }
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::watchpoint:
    case ProbeType::asyncwatchpoint:
    case ProbeType::tracepoint:
    case ProbeType::hardware:
    case ProbeType::software:
    {
      search_input = attach_point.target + ":" + attach_point.func;
      break;
    }
    case ProbeType::usdt:
    {
      auto target = attach_point.target;
      // If PID is specified, targets in symbol_stream will have the
      // "/proc/<PID>/root" prefix followed by an absolute path, so we make the
      // target absolute and add a leading wildcard.
      if (bpftrace_->pid() > 0)
      {
        if (!target.empty())
        {
          if (auto abs_target = abs_path(target))
            target = "*" + abs_target.value();
        }
        else
          target = "*";
      }
      auto ns = attach_point.ns.empty() ? "*" : attach_point.ns;
      search_input = target + ":" + ns + ":" + attach_point.func;
      break;
    }
    default:
      throw WildcardException(
          "Wildcard matches aren't available on probe type '" +
          attach_point.provider + "'");
  }

  return get_matches_for_probetype(probetype(attach_point.provider),
                                   attach_point.target,
                                   search_input);
}

std::set<std::string> ProbeMatcher::expand_probetype_kernel(
    const std::string& probe_type)
{
  if (has_wildcard(probe_type))
    return get_matches_in_stream(probe_type, false, *kernel_probe_list());
  else
    return { probe_type };
}

std::set<std::string> ProbeMatcher::expand_probetype_userspace(
    const std::string& probe_type)
{
  if (has_wildcard(probe_type))
    return get_matches_in_stream(probe_type, false, *userspace_probe_list());
  else
    return { probe_type };
}

void ProbeMatcher::list_structs(const std::string& search)
{
  auto structs = bpftrace_->btf_.get_all_structs();

  std::string search_input = search;
  // If verbose is on, structs will contain full definitions
  if (bt_verbose)
    search_input += " *{*}*";

  for (auto& match : get_matches_in_set(search_input, structs))
    std::cout << match << std::endl;
}

} // namespace bpftrace
