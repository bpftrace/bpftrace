#include <algorithm>
#include <cassert>
#include <iostream>

#include "probe_types.h"
#include "util/strings.h"

namespace bpftrace {

std::ostream &operator<<(std::ostream &os, ProbeType type)
{
  os << probetypeName(type);
  return os;
}

ProbeType probetype(const std::string &probeName)
{
  ProbeType retType = ProbeType::invalid;
  const std::string lowerProbeName = util::to_lower(probeName);
  auto v = std::ranges::find_if(PROBE_LIST,

                                [&lowerProbeName](const ProbeItem &p) {
                                  return (p.name == lowerProbeName ||
                                          p.aliases.contains(lowerProbeName));
                                });

  if (v != PROBE_LIST.end())
    retType = v->type;

  return retType;
}

std::string expand_probe_name(const std::string &orig_name)
{
  std::string expanded_name = util::to_lower(orig_name);
  auto v = std::ranges::find_if(PROBE_LIST, [&orig_name](const ProbeItem &p) {
    return (p.name == orig_name || p.aliases.contains(orig_name));
  });

  if (v != PROBE_LIST.end())
    expanded_name = v->name;

  return expanded_name;
}

std::string probetypeName(ProbeType t)
{
  // clang-format off
  switch (t)
  {
    case ProbeType::invalid:     return "invalid";     break;
    case ProbeType::special:     return "special";     break;
    case ProbeType::test:        return "test";        break;
    case ProbeType::benchmark:   return "benchmark";   break;
    case ProbeType::kprobe:      return "kprobe";      break;
    case ProbeType::kretprobe:   return "kretprobe";   break;
    case ProbeType::uprobe:      return "uprobe";      break;
    case ProbeType::uretprobe:   return "uretprobe";   break;
    case ProbeType::usdt:        return "usdt";        break;
    case ProbeType::tracepoint:  return "tracepoint";  break;
    case ProbeType::profile:     return "profile";     break;
    case ProbeType::interval:    return "interval";    break;
    case ProbeType::software:    return "software";    break;
    case ProbeType::hardware:    return "hardware";    break;
    case ProbeType::watchpoint:  return "watchpoint";  break;
    case ProbeType::fentry:      return "fentry";       break;
    case ProbeType::fexit:       return "fexit";    break;
    case ProbeType::iter:        return "iter";        break;
    case ProbeType::rawtracepoint: return "rawtracepoint";  break;
  }
  // clang-format on

  return {}; // unreached
}

} // namespace bpftrace
