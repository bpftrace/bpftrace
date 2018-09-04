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

bool search_probe(const std::string &probe, const std::string search)
{
  std::string s = search;
  char remove[] = "*.?";
  unsigned int i;

  // TODO: glob searching instead of discarding wildcards
  for (i = 0; i < strlen(remove); ++i)
  {
    s.erase(std::remove(s.begin(), s.end(), remove[i]), s.end());
  }

  if (probe.find(s) == std::string::npos)
    return true;

  return false;
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
}

void list_probes(const std::string &search)
{
  unsigned int i, j;
  std::string line, probe;

  // software
  // TODO: add here

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

  std::set<std::string> matches;
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

void list_probes()
{
  const std::string search = "";
  list_probes(search);
}

} // namespace bpftrace
