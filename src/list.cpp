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

bool search_probe(const std::string &probe, const std::string& search)
{
  try {
    std::string glob = "*";
    std::string regex = ".*";
    std::string s = replace_all(search,glob,regex);
    glob = "?";
    regex = ".";
    s = replace_all(s,glob,regex);
    s = "^" + s + "$";
    std::regex  re(s, std::regex::icase | std::regex::grep | std::regex::nosubs);
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

typedef std::tuple<std::string, std::string, std::string> uprobe_entry;
static std::vector<uprobe_entry> uprobes;

void uprobe_each(struct bcc_usdt *uprobe)
{
  uprobes.push_back(std::make_tuple(uprobe->provider, uprobe->name, uprobe->bin_path));
}

void list_probes(const std::string &search, int pid)
{
  unsigned int i, j;
  std::string line, probe;

  // software
  if (pid > 0) {
    void *ctx = bcc_usdt_new_frompid(pid, nullptr);
    if (ctx == nullptr) {
      std::cerr << "failed to initialize usdt context for pid: " << pid << std::endl;
      return;
    }
    bcc_usdt_foreach(ctx, uprobe_each);
    for (auto u : uprobes) {
      std::string provider, probe_name, bin_path;
      std::tie(provider, probe_name, bin_path) = u;
      std::string probe = "usdt:" + bin_path + ":" + probe_name;
      if (search_probe(probe, search))
        continue;
      std::cout << probe << std::endl;
    }
    bcc_usdt_close(ctx);
  }

  // hardware
  // TODO: add here

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
      if (search_probe(probe, search))
        continue;
      std::cout << probe << std::endl;
    }
  }

  // kprobes
  std::cout << std::endl;
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
      if (search_probe(probe, search))
        continue;
    }

    std::cout << probe << std::endl;
  }

}

} // namespace bpftrace
