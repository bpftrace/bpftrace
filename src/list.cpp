#include <signal.h>
#include <sys/types.h>
#include <dirent.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <regex>
#include <vector>
#include <string>

#include "bcc_usdt.h"

#include "list.h"
#include "bpftrace.h"

namespace bpftrace {

const std::string kprobe_path = "/sys/kernel/debug/tracing/available_filter_functions";
const std::string tp_path = "/sys/kernel/debug/tracing/events";

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

typedef std::tuple<std::string, std::string, std::string> usdt_entry;
static std::vector<usdt_entry> usdt_probes;

void usdt_each(struct bcc_usdt *usdt)
{
  usdt_probes.emplace_back(usdt->provider, usdt->name, usdt->bin_path);
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
  std::regex re("^	field:.*;$", std::regex::icase | std::regex::grep | std::regex::nosubs |
                                     std::regex::optimize);
  std::string line;

  if (format_file.fail())
  {
    std::cerr << "ERROR: tracepoint format file not found: " << format_file_path << std::endl;
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

void list_probes(const std::string &search_input, int pid)
{
  std::string search = search_input;

  std::smatch probe_match;
  std::regex probe_regex(":.*");
  std::regex_search ( search, probe_match, probe_regex );

  // replace alias name with full name
  if (probe_match.size())
  {
    auto pos = probe_match.position(0);
    auto probe_name =  probetypeName(search.substr(0, probe_match.position(0)));
    search = probe_name + search.substr(pos, search.length());
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
  std::regex re(s, std::regex::icase | std::regex::grep | std::regex::nosubs | std::regex::optimize);

  // software
  list_probes_from_list(SW_PROBE_LIST, "software", search, re);

  // hardware
  list_probes_from_list(HW_PROBE_LIST, "hardware", search, re);

  // usdt
  if (pid > 0) {
    void *ctx = bcc_usdt_new_frompid(pid, nullptr);
    if (ctx == nullptr) {
      std::cerr << "failed to initialize usdt context for pid: " << pid << std::endl;
      if (kill(pid, 0) == -1 && errno == ESRCH) {
        std::cerr << "hint: process not running" << std::endl;
      }
      return;
    }
    bcc_usdt_foreach(ctx, usdt_each);
    for (const auto &u : usdt_probes) {
      std::string probe = "usdt:" + std::get<2>(u) + ":" + std::get<1>(u);
      if (!search.empty())
      {
        if (search_probe(probe, re))
          continue;
      }
      std::cout << probe << std::endl;
    }
    bcc_usdt_close(ctx);
  }

  // tracepoints
  std::string probe;
  std::vector<std::string> cats;
  list_dir(tp_path, cats);
  for (const std::string &cat : cats)
  {
    if (cat == "." || cat == ".." || cat == "enable" || cat == "filter")
      continue;
    std::vector<std::string> events = std::vector<std::string>();
    list_dir(tp_path + "/" + cat, events);
    for (const std::string &event : events)
    {
      if (event == "." || event == ".." || event == "enable" || event == "filter")
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

  // Optimization: If the search expression starts with "t" (tracepoint) there is
  // no need to search for kprobes.
  if (search[0] == 't')
      return;

  // kprobes
  std::ifstream file(kprobe_path);
  if (file.fail())
  {
    std::cerr << strerror(errno) << ": " << kprobe_path << std::endl;
    return;
  }

  std::string line;
  size_t loc;
  while (std::getline(file, line))
  {
    loc = line.find_first_of(" ");
    if (loc == std::string::npos)
      probe = "kprobe:" + line;
    else
      probe = "kprobe:" + line.substr(0, loc);

    if (!search.empty())
    {
      if (search_probe(probe, re))
        continue;
    }

    std::cout << probe << std::endl;
  }

}

} // namespace bpftrace
