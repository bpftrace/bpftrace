#include <iostream>

#include "bpftrace.h"
#include "attached_probe.h"

namespace ebpf {
namespace bpftrace {

std::string typestr(Type t)
{
  switch (t)
  {
    case Type::none:     return "none";     break;
    case Type::integer:  return "integer";  break;
    case Type::quantize: return "quantize"; break;
    case Type::count:    return "count";    break;
    default: abort();
  }
}

bpf_probe_attach_type attachtype(ProbeType t)
{
  switch (t)
  {
    case ProbeType::kprobe:    return BPF_PROBE_ENTRY;  break;
    case ProbeType::kretprobe: return BPF_PROBE_RETURN; break;
    default: abort();
  }
}

bpf_prog_type progtype(ProbeType t)
{
  switch (t)
  {
    case ProbeType::kprobe:    return BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::kretprobe: return BPF_PROG_TYPE_KPROBE; break;
    default: abort();
  }
}

int BPFtrace::add_probe(ast::Probe &p)
{
  Probe probe;
  probe.attach_point = p.attach_point;
  probe.name = p.name;
  if (p.type == "kprobe")
    probe.type = ProbeType::kprobe;
  else if (p.type == "kretprobe")
    probe.type = ProbeType::kretprobe;
  else
    return -1;
  probes_.push_back(probe);
  return 0;
}

int BPFtrace::run()
{
  std::vector<std::unique_ptr<AttachedProbe>> attached_probes;
  for (Probe &probe : probes_)
  {
    auto func = sections_.find(probe.name);
    if (func == sections_.end())
    {
      std::cerr << "Code not generated for probe: " << probe.name << std::endl;
      return -1;
    }
    try
    {
      attached_probes.push_back(std::make_unique<AttachedProbe>(probe, func->second));
    }
    catch (std::runtime_error e)
    {
      std::cerr << e.what() << std::endl;
      return -1;
    }
  }

  // TODO wait here while script is running
  getchar();

  return 0;
}

int BPFtrace::print_maps()
{
  for(auto &mapmap : maps_)
  {
    Map &map = *mapmap.second.get();
    auto map_args = map_args_.find(map.name_);
    if (map_args == map_args_.end())
      abort();

    int key_elems = map_args->second.size();
    if (key_elems == 0) key_elems = 1;
    auto old_key = std::vector<uint64_t>(key_elems);
    auto key = std::vector<uint64_t>(key_elems);
    uint64_t value;
    int err;

    err = bpf_get_next_key(map.mapfd_, old_key.data(), key.data());
    if (err)
      key = old_key;

    do
    {
      std::cout << map.name_ << "[ ";
      for (int i=0; i<key_elems; i++)
        std::cout << key.at(i) << " ";
      std::cout << "]: ";

      err = bpf_lookup_elem(map.mapfd_, key.data(), &value);
      std::cout << value << std::endl;
      if (err)
      {
        std::cerr << "Error looking up elem: " << err << std::endl;
        return -1;
      }
      old_key = key;
    }
    while (bpf_get_next_key(map.mapfd_, old_key.data(), key.data()) == 0);
  }
}

} // namespace bpftrace
} // namespace ebpf
