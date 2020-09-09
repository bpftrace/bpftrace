#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <regex>
#include <vector>
#include <string>

#include "bpftrace.h"
#include "btf.h"
#include "list.h"
#include "log.h"
#include "utils.h"

namespace bpftrace {

inline bool search_probe(const std::string &probe, const std::regex& re)
{
  try {
    if (std::regex_search(probe, re))
      return false;
    else
      return true;
   } catch(std::regex_error& e) {
       return true;
  }
}

void list_dir(const std::string path, std::vector<std::string> &files)
{
  // yes, I know about std::filesystem::directory_iterator, but no, it wasn't available
  DIR *dp;
  struct dirent *dep;
  if ((dp = opendir(path.c_str())) == NULL)
    return;

  while ((dep = readdir(dp)) != NULL)
    files.push_back(std::string(dep->d_name));

  closedir(dp);
}

void list_probes_from_list(const std::vector<ProbeListItem> &probes_list,
                           const std::string &probetype, const std::string &search,
                           const std::regex& re)
{
  std::string probe;

  for (auto &probeListItem : probes_list)
  {
    probe = probetype + ":" + probeListItem.path + ":";

    if (!search.empty())
    {
      if (search_probe(probe, re))
        continue;
    }

    std::cout << probe  << std::endl;
  }
}

void print_tracepoint_args(const std::string &category, const std::string &event)
{
  std::string format_file_path = tp_path + "/" + category + "/" + event + "/format";
  std::ifstream format_file(format_file_path.c_str());
  std::regex re("^\tfield:.*;$", std::regex::icase | std::regex::grep |
                                 std::regex::nosubs | std::regex::optimize);
  std::string line;

  if (format_file.fail())
  {
    LOG(ERROR) << "tracepoint format file not found: " << format_file_path;
    return;
  }

  // Skip lines until the first empty line
  do {
    getline(format_file, line);
  } while (line.length() > 0);

  for (; getline(format_file, line); )
  {
    try {
      if (std::regex_match(line, re))
      {
        unsigned idx = line.find(":") + 1;
        line = line.substr(idx);
        idx = line.find(";") + 1;
        line = line.substr(0, idx);
        std::cout << "    " << line << std::endl;
      }
    } catch(std::regex_error& e) {
      return;
    }
  }
}

static void list_uprobes(const BPFtrace& bpftrace,
                         const std::string& probe_name,
                         const std::string& search,
                         const std::regex& re)
{
    std::unique_ptr<std::istream> symbol_stream;
    // Given path (containing a possible wildcard)
    std::string path;
    bool show_all = false;

    if (bpftrace.pid() > 0)
    {
      path = get_pid_exe(bpftrace.pid());
      path = path_for_pid_mountns(bpftrace.pid(), path);
    }
    else if (probe_name == "uprobe" || probe_name == "uretprobe")
    {
      path = search;
      erase_prefix(path); // remove "u[ret]probe:" prefix
      show_all = path.find(':') == std::string::npos;
      path = erase_prefix(path); // extract "path" prefix from "path:fun"

      auto abs_paths = resolve_binary_path(path);
      if (abs_paths.empty())
      {
        LOG(ERROR) << probe_name << " target '" << path
                   << "' does not exist or is not executable";
        return;
      }
    }

    if (!path.empty())
    {
      symbol_stream = std::make_unique<std::istringstream>(
          bpftrace.extract_func_symbols_from_path(path));

      std::string line;
      while (std::getline(*symbol_stream, line))
      {
        std::string probe = (probe_name.empty() ? "uprobe" : probe_name) + ":" +
                            line;
        if (show_all || search.empty() || !search_probe(probe, re))
          std::cout << probe << std::endl;
      }
    }
}

static void list_usdt(const BPFtrace& bpftrace,
                      const std::string& probe_name,
                      const std::string& search,
                      const std::regex& re)
{
  usdt_probe_list usdt_probes;
  bool show_all = false;
  if (bpftrace.pid() > 0)
  {
    // PID takes precedence over path, so path from search expression will be
    // ignored if pid specified
    usdt_probes = USDTHelper::probes_for_pid(bpftrace.pid());
  }
  else if (probe_name == "usdt")
  {
    std::string usdt_path = search;
    erase_prefix(usdt_path); // remove the "usdt:" prefix;
    show_all = usdt_path.find(':') == std::string::npos;
    usdt_path = erase_prefix(usdt_path); // extract "path" from "path:ns:fun"
    auto paths = resolve_binary_path(usdt_path, bpftrace.pid());
    if (!paths.empty())
    {
      for (auto& path : paths)
      {
        auto path_usdt_probes = USDTHelper::probes_for_path(path);
        usdt_probes.insert(usdt_probes.end(),
                           path_usdt_probes.begin(),
                           path_usdt_probes.end());
      }
    }
    else
    {
      LOG(ERROR) << "usdt target '" << usdt_path
                 << "' does not exist or is not executable";
      return;
    }
  }

  for (auto const& usdt_probe : usdt_probes)
  {
    std::string path = usdt_probe.path;
    std::string provider = usdt_probe.provider;
    std::string fname = usdt_probe.name;
    std::string probe = "usdt:" + path + ":" + provider + ":" + fname;
    if (show_all || search.empty() || !search_probe(probe, re))
      std::cout << probe << std::endl;
  }
}

static void list_tracepoints(const std::string& search, const std::regex& re)
{
  std::string probe;
  std::vector<std::string> cats;
  list_dir(tp_path, cats);
  for (const std::string& cat : cats)
  {
    if (cat == "." || cat == ".." || cat == "enable" || cat == "filter")
      continue;
    std::vector<std::string> events = std::vector<std::string>();
    list_dir(tp_path + "/" + cat, events);
    for (const std::string& event : events)
    {
      if (event == "." || event == ".." || event == "enable" ||
          event == "filter")
        continue;
      probe = "tracepoint:" + cat + ":" + event;

      if (!search.empty())
      {
        if (search_probe(probe, re))
          continue;
      }

      std::cout << probe << std::endl;
      if (bt_verbose)
        print_tracepoint_args(cat, event);
    }
  }
}

static void list_kprobes(const std::string& search,
                         const std::regex& re,
                         const bool retprobe = false)
{
  std::ifstream file(kprobe_path);
  if (file.fail())
  {
    LOG(ERROR) << strerror(errno) << ": " << kprobe_path;
    return;
  }

  std::string probe, line;
  size_t loc;
  while (std::getline(file, line))
  {
    loc = line.find_first_of(" ");
    probe = retprobe ? "kretprobe:" : "kprobe:";
    if (loc == std::string::npos)
      probe += line;
    else
      probe += line.substr(0, loc);

    if (!search.empty())
    {
      if (search_probe(probe, re))
        continue;
    }

    std::cout << probe << std::endl;
  }
}

void list_probes(const BPFtrace& bpftrace, const std::string& search_input)
{
  std::string search = search_input;
  std::string probe_name;
  bool has_wildcard_in_probe = false;
  std::regex re;

  std::smatch probe_match;
  std::regex probe_regex(":.*");
  std::regex_search(search, probe_match, probe_regex);

  // replace alias name with full name
  if (probe_match.size())
  {
    auto pos = probe_match.position(0);
    probe_name = probetypeName(search.substr(0, probe_match.position(0)));
    search = probe_name + search.substr(pos, search.length());
    for (char c : probe_name)
      has_wildcard_in_probe = has_wildcard_in_probe || c == '*' || c == '?';
  }

  std::string s = "^";
  for (char c : search)
  {
    if (c == '*')
      s += ".*";
    else if (c == '?')
      s += '.';
    else
      s += c;
  }
  s += '$';
  try
  {
    re = std::regex(s,
                    std::regex::icase | std::regex::grep | std::regex::nosubs |
                        std::regex::optimize);
  }
  catch (std::regex_error& e)
  {
    LOG(ERROR) << "invalid character in search expression.";
    return;
  }

  bool list_all = (bpftrace.pid() == 0) &&
                  (has_wildcard_in_probe || probe_name.empty());

  // software
  if (list_all || probe_name == "software")
    list_probes_from_list(SW_PROBE_LIST, "software", search, re);

  // hardware
  if (list_all || probe_name == "hardware")
    list_probes_from_list(HW_PROBE_LIST, "hardware", search, re);

  // uprobe
  if (bpftrace.pid() > 0 || probe_name == "uprobe" || probe_name == "uretprobe")
    list_uprobes(bpftrace, probe_name, search, re);

  // usdt
  if (bpftrace.pid() > 0 || probe_name == "usdt")
    list_usdt(bpftrace, probe_name, search, re);

  // tracepoints
  if (list_all || probe_name == "tracepoint")
    list_tracepoints(search, re);

  // kprobes
  if (list_all || probe_name == "kprobe" || probe_name == "kretprobe")
    list_kprobes(search, re, probe_name == "kretprobe");

  // kfuncs
  if (list_all || probe_name == "kfunc" || probe_name == "kretfunc")
    bpftrace.btf_.display_kfunc(search.empty() ? nullptr : &re,
                                probe_name == "kretfunc");

  // struct / union / enum
  if (probe_name.empty() &&
      std::regex_search(search, std::regex("^(struct|union|enum) ")))
    bpftrace.btf_.display_structs(search.empty() ? nullptr : &re);
}

} // namespace bpftrace
