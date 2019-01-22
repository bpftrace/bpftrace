#include <sys/types.h>
#include <dirent.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <regex>
#include <vector>
#include <string>

#include "list.h"
#include "bpftrace.h"

namespace bpftrace {

const std::string kprobe_path = "/sys/kernel/debug/tracing/available_filter_functions";
const std::string tp_path = "/sys/kernel/debug/tracing/events";

std::string replace_all(const std::string &str, const std::string &from,
			const std::string &to)
{
    std::string result(str);
    std::string::size_type
        index = 0,
        from_len = from.size(),
        to_len = to.size();
    while ((index = result.find(from, index)) != std::string::npos) {
        result.replace(index, from_len, to);
        index += to_len;
    }
    return result;
}

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

void list_probes(const std::string &search)
{
  unsigned int i, j;
  std::string line, probe;
  std::string glob = "*";
  std::string regex = ".*";
  std::string s = replace_all(search,glob,regex);
  glob = "?";
  regex = ".";
  s = replace_all(s,glob,regex);
  s = "^" + s + "$";
  std::regex re(s, std::regex::icase | std::regex::grep | std::regex::nosubs | std::regex::optimize);

  // software
  list_probes_from_list(SW_PROBE_LIST, "software", search, re);

  // hardware
  list_probes_from_list(HW_PROBE_LIST, "hardware", search, re);

  // tracepoints
  std::vector<std::string> cats = std::vector<std::string>();
  list_dir(tp_path, cats);
  for (i = 0; i < cats.size(); i++)
  {
    if (cats[i] == "." || cats[i] == ".." || cats[i] == "enable" || cats[i] == "filter")
      continue;
    std::vector<std::string> events = std::vector<std::string>();
    list_dir(tp_path + "/" + cats[i], events);
    for (j = 0; j < events.size(); j++)
    {
      if (events[j] == "." || events[j] == ".." || events[j] == "enable" || events[j] == "filter")
        continue;
      probe = "tracepoint:" + cats[i] + ":" + events[j];

      if (!search.empty())
      {
        if (search_probe(probe, re))
          continue;
      }

      std::cout << probe << std::endl;
      if (bt_verbose)
        print_tracepoint_args(cats[i], events[j]);
    }
  }

  // Optimization: If the search expression starts with "t" (tracepoint) there is
  // no need to search for kprobes.
  if (search.rfind("t", 0) == 0)
      return;

  // kprobes
  std::ifstream file(kprobe_path);
  if (file.fail())
  {
    std::cerr << strerror(errno) << ": " << kprobe_path << std::endl;
    return;
  }

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

void list_probes()
{
  const std::string search = "";
  list_probes(search);
}

} // namespace bpftrace
