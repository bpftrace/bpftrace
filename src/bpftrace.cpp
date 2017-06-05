#include <iomanip>
#include <iostream>
#include <sstream>

#include "bpftrace.h"
#include "attached_probe.h"

namespace bpftrace {

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
    int err;
    if (map.type_ == Type::quantize)
      err = print_map_quantize(map);
    else
      err = print_map(map);

    if (err)
      return err;
  }

  return 0;
}

int BPFtrace::print_map(Map &map)
{
  int key_elems = map.args_.size();
  if (key_elems == 0) key_elems = 1;
  auto old_key = std::vector<uint64_t>(key_elems);
  auto key = std::vector<uint64_t>(key_elems);
  int err;

  err = bpf_get_next_key(map.mapfd_, old_key.data(), key.data());
  if (err)
    key = old_key;

  do
  {
    std::cout << map.name_ << argument_list(key, map.args_.size()) << ": ";

    uint64_t value;
    err = bpf_lookup_elem(map.mapfd_, key.data(), &value);
    if (err)
    {
      std::cerr << "Error looking up elem: " << err << std::endl;
      return -1;
    }
    std::cout << value << std::endl;

    old_key = key;
  }
  while (bpf_get_next_key(map.mapfd_, old_key.data(), key.data()) == 0);

  std::cout << std::endl;

  return 0;
}

int BPFtrace::print_map_quantize(Map &map)
{
  // A quantize-map adds an extra 8 bytes onto the end of its key for storing
  // the bucket number.
  // e.g. A map defined as: @x[1, 2] = @quantize(3);
  // would actually be stored with the key: [1, 2, 3]

  int key_elems = map.args_.size();
  auto old_key = std::vector<uint64_t>(key_elems + 1);
  auto key = std::vector<uint64_t>(key_elems + 1);
  int err;

  std::map<std::vector<uint64_t>, std::vector<uint64_t>> values;

  err = bpf_get_next_key(map.mapfd_, old_key.data(), key.data());
  if (err)
    key = old_key;

  do
  {
    auto key_prefix = std::vector<uint64_t>(key_elems);
    int bucket = key.at(key_elems);

    for (int i=0; i<key_elems; i++)
      key_prefix.at(i) = key.at(i);

    uint64_t value;
    err = bpf_lookup_elem(map.mapfd_, key.data(), &value);
    if (err)
    {
      std::cerr << "Error looking up elem: " << err << std::endl;
      return -1;
    }

    if (values.find(key_prefix) == values.end())
    {
      // New key - create a list of buckets for it
      values[key_prefix] = std::vector<uint64_t>(65);
    }
    values[key_prefix].at(bucket) = value;

    old_key = key;
  }
  while (bpf_get_next_key(map.mapfd_, old_key.data(), key.data()) == 0);

  for (auto &map_elem : values)
  {
    std::cout << map.name_ << argument_list(map_elem.first) << ": " << std::endl;

    print_quantize(map_elem.second);

    std::cout << std::endl;
  }

  return 0;
}

int BPFtrace::print_quantize(std::vector<uint64_t> values)
{
  int max_index = -1;
  int max_value = 0;

  for (size_t i = 0; i < values.size(); i++)
  {
    int v = values.at(i);
    if (v != 0)
      max_index = i;
    if (v > max_value)
      max_value = v;
  }

  if (max_index == -1)
    return 0;

  for (int i = 0; i <= max_index; i++)
  {
    std::ostringstream header;
    if (i == 0)
    {
      header << "[0, 1]";
    }
    else
    {
      header << "[" << quantize_index_label(i);
      header << ", " << quantize_index_label(i+1) << ")";
    }

    int max_width = 52;
    int bar_width = values.at(i)/(float)max_value*max_width;
    std::string bar(bar_width, '@');

    std::cout << std::setw(16) << std::left << header.str()
              << std::setw(8) << std::right << values.at(i)
              << " |" << std::setw(max_width) << std::left << bar << "|"
              << std::endl;
  }

  return 0;
}

std::string BPFtrace::quantize_index_label(int power)
{
  char suffix = '\0';
  if (power >= 40)
  {
    suffix = 'T';
    power -= 40;
  }
  else if (power >= 30)
  {
    suffix = 'G';
    power -= 30;
  }
  else if (power >= 20)
  {
    suffix = 'M';
    power -= 20;
  }
  else if (power >= 10)
  {
    suffix = 'k';
    power -= 10;
  }

  std::ostringstream label;
  label << (1<<power);
  if (suffix)
    label << suffix;
  return label.str();
}

} // namespace bpftrace
