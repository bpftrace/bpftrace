#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <sstream>
#include <sys/epoll.h>

#include "bcc_syms.h"
#include "perf_reader.h"

#include "bpftrace.h"
#include "attached_probe.h"
#include "triggers.h"

namespace bpftrace {

int BPFtrace::add_probe(ast::Probe &p)
{
  if (p.type == "BEGIN")
  {
    Probe probe;
    probe.path = "/proc/self/exe";
    probe.attach_point = "BEGIN_trigger";
    probe.type = probetype(p.type);
    probe.prog_name = p.name();
    probe.name = p.name();
    special_probes_.push_back(probe);
    return 0;
  }
  else if (p.type == "END")
  {
    Probe probe;
    probe.path = "/proc/self/exe";
    probe.attach_point = "END_trigger";
    probe.type = probetype(p.type);
    probe.prog_name = p.name();
    probe.name = p.name();
    special_probes_.push_back(probe);
    return 0;
  }

  ast::AttachPointList expanded_attach_points;
  for (std::string attach_point : *p.attach_points)
  {
    if (attach_point.find("*") != std::string::npos)
    {
      std::string file_name;
      switch (probetype(p.type))
      {
        case ProbeType::kprobe:
        case ProbeType::kretprobe:
          file_name = "/sys/kernel/debug/tracing/available_filter_functions";
          break;
        default:
          std::cerr << "Wildcard matches aren't available on probe type '"
                    << p.type << "'" << std::endl;
          return 1;
      }
      auto matches = find_wildcard_matches(attach_point, file_name);
      expanded_attach_points.insert(expanded_attach_points.end(),
          matches.begin(), matches.end());
      continue;
    }

    expanded_attach_points.push_back(attach_point);
  }

  for (std::string attach_point : expanded_attach_points)
  {
    Probe probe;
    probe.path = p.path;
    probe.attach_point = attach_point;
    probe.type = probetype(p.type);
    probe.prog_name = p.name();
    probe.name = p.name(attach_point);
    probes_.push_back(probe);
  }
  return 0;
}

std::set<std::string> BPFtrace::find_wildcard_matches(std::string attach_point, std::string file_name)
{
  // Turn glob into a regex
  attach_point = "^" + std::regex_replace(attach_point, std::regex("\\*"), "[^\\s]*");
  std::regex attach_point_regex(attach_point);
  std::smatch match;

  std::ifstream file(file_name);
  std::string line;
  std::set<std::string> matches;
  while (std::getline(file, line))
  {
    if (std::regex_search(line, match, attach_point_regex))
    {
      matches.insert(match[0]);
    }
  }
  return matches;
}

int BPFtrace::num_probes() const
{
  return special_probes_.size() + probes_.size();
}

void perf_event_printer(void *cb_cookie, void *data, int size)
{
  auto bpftrace = static_cast<BPFtrace*>(cb_cookie);
  auto printf_id = *static_cast<uint64_t*>(data);
  auto arg_data = static_cast<uint8_t*>(data) + sizeof(uint64_t);

  auto fmt = std::get<0>(bpftrace->printf_args_[printf_id]).c_str();
  auto args = std::get<1>(bpftrace->printf_args_[printf_id]);
  std::vector<uint64_t> arg_values;
  std::vector<std::string> resolved_symbols;
  for (auto arg : args)
  {
    switch (arg.type)
    {
      case Type::integer:
        arg_values.push_back(*(uint64_t*)arg_data);
        break;
      case Type::string:
        arg_values.push_back((uint64_t)arg_data);
        break;
      case Type::sym:
        resolved_symbols.push_back(bpftrace->resolve_sym(*(uint64_t*)arg_data));
        arg_values.push_back((uint64_t)resolved_symbols.back().c_str());
        break;
      case Type::usym:
        resolved_symbols.push_back(bpftrace->resolve_usym(*(uint64_t*)arg_data));
        arg_values.push_back((uint64_t)resolved_symbols.back().c_str());
        break;
      default:
        abort();
    }
    arg_data +=  arg.size;
  }

  switch (args.size())
  {
    case 0:
      printf(fmt);
      break;
    case 1:
      printf(fmt, arg_values.at(0));
      break;
    case 2:
      printf(fmt, arg_values.at(0), arg_values.at(1));
      break;
    case 3:
      printf(fmt, arg_values.at(0), arg_values.at(1), arg_values.at(2));
      break;
    case 4:
      printf(fmt, arg_values.at(0), arg_values.at(1), arg_values.at(2),
          arg_values.at(3));
      break;
    case 5:
      printf(fmt, arg_values.at(0), arg_values.at(1), arg_values.at(2),
          arg_values.at(3), arg_values.at(4));
      break;
    case 6:
      printf(fmt, arg_values.at(0), arg_values.at(1), arg_values.at(2),
          arg_values.at(3), arg_values.at(4), arg_values.at(5));
      break;
    default:
      abort();
  }
}

void perf_event_lost(uint64_t lost)
{
  printf("Lost %lu events\n", lost);
}

std::unique_ptr<AttachedProbe> BPFtrace::attach_probe(Probe &probe)
{
  auto func = sections_.find(probe.prog_name);
  if (func == sections_.end())
  {
    std::cerr << "Code not generated for probe: " << probe.name << std::endl;
    return nullptr;
  }
  try
  {
    return std::make_unique<AttachedProbe>(probe, func->second);
  }
  catch (std::runtime_error e)
  {
    std::cerr << e.what() << std::endl;
  }
  return nullptr;
}

int BPFtrace::run()
{
  for (Probe &probe : special_probes_)
  {
    auto attached_probe = attach_probe(probe);
    if (attached_probe == nullptr)
      return -1;
    special_attached_probes_.push_back(std::move(attached_probe));
  }

  int epollfd = setup_perf_events();
  if (epollfd < 0)
    return epollfd;

  BEGIN_trigger();

  for (Probe &probe : probes_)
  {
    auto attached_probe = attach_probe(probe);
    if (attached_probe == nullptr)
      return -1;
    attached_probes_.push_back(std::move(attached_probe));
  }

  poll_perf_events(epollfd);
  attached_probes_.clear();

  END_trigger();
  poll_perf_events(epollfd, 100);
  special_attached_probes_.clear();

  return 0;
}

int BPFtrace::setup_perf_events()
{
  int epollfd = epoll_create1(EPOLL_CLOEXEC);
  if (epollfd == -1)
  {
    std::cerr << "Failed to create epollfd" << std::endl;
    return -1;
  }

  std::vector<int> cpus = ebpf::get_online_cpus();
  for (int cpu : cpus)
  {
    int page_cnt = 8;
    void *reader = bpf_open_perf_buffer(&perf_event_printer, &perf_event_lost, this, -1, cpu, page_cnt);
    if (reader == nullptr)
    {
      std::cerr << "Failed to open perf buffer" << std::endl;
      return -1;
    }

    struct epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.ptr = reader;
    int reader_fd = perf_reader_fd((perf_reader*)reader);

    bpf_update_elem(perf_event_map_->mapfd_, &cpu, &reader_fd, 0);
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, reader_fd, &ev) == -1)
    {
      std::cerr << "Failed to add perf reader to epoll" << std::endl;
      return -1;
    }
  }
  return epollfd;
}

void BPFtrace::poll_perf_events(int epollfd, int timeout)
{
  std::vector<int> cpus = ebpf::get_online_cpus();
  int ncpus = cpus.size();
  auto events = std::vector<struct epoll_event>(ncpus);
  while (true)
  {
    int ready = epoll_wait(epollfd, events.data(), ncpus, timeout);
    if (ready <= 0)
    {
      return;
    }

    for (int i=0; i<ready; i++)
    {
      perf_reader_event_read((perf_reader*)events[i].data.ptr);
    }
  }
  return;
}

int BPFtrace::print_maps()
{
  for(auto &mapmap : maps_)
  {
    IMap &map = *mapmap.second.get();
    int err;
    if (map.type_.type == Type::quantize)
      err = print_map_quantize(map);
    else
      err = print_map(map);

    if (err)
      return err;
  }

  return 0;
}

int BPFtrace::print_map(IMap &map)
{
  std::vector<uint8_t> old_key;
  try
  {
    old_key = find_empty_key(map, map.key_.size());
  }
  catch (std::runtime_error &e)
  {
    std::cerr << "Error getting key for map '" << map.name_ << "': "
              << e.what() << std::endl;
    return -2;
  }
  auto key(old_key);

  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> values_by_key;

  while (bpf_get_next_key(map.mapfd_, old_key.data(), key.data()) == 0)
  {
    int value_size = map.type_.size;
    if (map.type_.type == Type::count)
      value_size *= ncpus_;
    auto value = std::vector<uint8_t>(value_size);
    int err = bpf_lookup_elem(map.mapfd_, key.data(), value.data());
    if (err)
    {
      std::cerr << "Error looking up elem: " << err << std::endl;
      return -1;
    }

    values_by_key.push_back({key, value});

    old_key = key;
  }

  if (map.type_.type == Type::count)
  {
    std::sort(values_by_key.begin(), values_by_key.end(), [&](auto &a, auto &b)
    {
      return reduce_value(a.second, ncpus_) < reduce_value(b.second, ncpus_);
    });
  }
  else
  {
    sort_by_key(map.key_.args_, values_by_key);
  };

  for (auto &pair : values_by_key)
  {
    auto key = pair.first;
    auto value = pair.second;

    std::cout << map.name_ << map.key_.argument_value_list(*this, key) << ": ";

    if (map.type_.type == Type::stack)
      std::cout << get_stack(*(uint32_t*)value.data(), false, 8);
    else if (map.type_.type == Type::ustack)
      std::cout << get_stack(*(uint32_t*)value.data(), true, 8);
    else if (map.type_.type == Type::sym)
      std::cout << resolve_sym(*(uint64_t*)value.data());
    else if (map.type_.type == Type::usym)
      std::cout << resolve_usym(*(uint64_t*)value.data());
    else if (map.type_.type == Type::string)
      std::cout << value.data() << std::endl;
    else if (map.type_.type == Type::count)
      std::cout << reduce_value(value, ncpus_) << std::endl;
    else
      std::cout << *(int64_t*)value.data() << std::endl;
  }

  std::cout << std::endl;

  return 0;
}

int BPFtrace::print_map_quantize(IMap &map)
{
  // A quantize-map adds an extra 8 bytes onto the end of its key for storing
  // the bucket number.
  // e.g. A map defined as: @x[1, 2] = @quantize(3);
  // would actually be stored with the key: [1, 2, 3]

  std::vector<uint8_t> old_key;
  try
  {
    old_key = find_empty_key(map, map.key_.size() + 8);
  }
  catch (std::runtime_error &e)
  {
    std::cerr << "Error getting key for map '" << map.name_ << "': "
              << e.what() << std::endl;
    return -2;
  }
  auto key(old_key);

  std::map<std::vector<uint8_t>, std::vector<uint64_t>> values_by_key;

  while (bpf_get_next_key(map.mapfd_, old_key.data(), key.data()) == 0)
  {
    auto key_prefix = std::vector<uint8_t>(map.key_.size());
    int bucket = key.at(map.key_.size());

    for (size_t i=0; i<map.key_.size(); i++)
      key_prefix.at(i) = key.at(i);

    int value_size = map.type_.size * ncpus_;
    auto value = std::vector<uint8_t>(value_size);
    int err = bpf_lookup_elem(map.mapfd_, key.data(), value.data());
    if (err)
    {
      std::cerr << "Error looking up elem: " << err << std::endl;
      return -1;
    }

    if (values_by_key.find(key_prefix) == values_by_key.end())
    {
      // New key - create a list of buckets for it
      values_by_key[key_prefix] = std::vector<uint64_t>(65);
    }
    values_by_key[key_prefix].at(bucket) = reduce_value(value, ncpus_);

    old_key = key;
  }

  // Sort based on sum of counts in all buckets
  std::vector<std::pair<std::vector<uint8_t>, uint64_t>> total_counts_by_key;
  for (auto &map_elem : values_by_key)
  {
    int sum = 0;
    for (size_t i=0; i<map_elem.second.size(); i++)
    {
      sum += map_elem.second.at(i);
    }
    total_counts_by_key.push_back({map_elem.first, sum});
  }
  std::sort(total_counts_by_key.begin(), total_counts_by_key.end(), [&](auto &a, auto &b)
  {
    return a.second < b.second;
  });

  for (auto &key_count : total_counts_by_key)
  {
    auto &key = key_count.first;
    auto &value = values_by_key[key];
    std::cout << map.name_ << map.key_.argument_value_list(*this, key) << ": " << std::endl;

    print_quantize(value);

    std::cout << std::endl;
  }

  return 0;
}

int BPFtrace::print_quantize(const std::vector<uint64_t> &values) const
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

uint64_t BPFtrace::reduce_value(const std::vector<uint8_t> &value, int ncpus)
{
  uint64_t sum = 0;
  for (int i=0; i<ncpus; i++)
  {
    sum += *(uint64_t*)(value.data() + i*sizeof(uint64_t*));
  }
  return sum;
}

std::vector<uint8_t> BPFtrace::find_empty_key(IMap &map, size_t size) const
{
  if (size == 0) size = 8;
  auto key = std::vector<uint8_t>(size);
  int value_size = map.type_.size;
  if (map.type_.type == Type::count || map.type_.type == Type::quantize)
    value_size *= ncpus_;
  auto value = std::vector<uint8_t>(value_size);

  if (bpf_lookup_elem(map.mapfd_, key.data(), value.data()))
    return key;

  for (auto &elem : key) elem = 0xff;
  if (bpf_lookup_elem(map.mapfd_, key.data(), value.data()))
    return key;

  for (auto &elem : key) elem = 0x55;
  if (bpf_lookup_elem(map.mapfd_, key.data(), value.data()))
    return key;

  throw std::runtime_error("Could not find empty key");
}

std::string BPFtrace::get_stack(uint32_t stackid, bool ustack, int indent)
{
  auto stack_trace = std::vector<uint64_t>(MAX_STACK_SIZE);
  int err = bpf_lookup_elem(stackid_map_->mapfd_, &stackid, stack_trace.data());
  if (err)
  {
    std::cerr << "Error looking up stack id " << stackid << ": " << err << std::endl;
    return "";
  }

  std::ostringstream stack;
  std::string padding(indent, ' ');

  stack << "\n";
  for (auto &addr : stack_trace)
  {
    if (addr == 0)
      break;
    if (!ustack)
      stack << padding << resolve_sym(addr, true) << std::endl;
    else
      stack << padding << resolve_usym(addr) << std::endl;
  }

  return stack.str();
}

std::string BPFtrace::resolve_sym(uint64_t addr, bool show_offset)
{
  struct bcc_symbol sym;
  std::ostringstream symbol;

  if (ksyms.resolve_addr(addr, &sym))
  {
    symbol << sym.name;
    if (show_offset)
      symbol << "+" << sym.offset;
  }
  else
  {
    symbol << (void*)addr;
  }

  return symbol.str();
}

std::string BPFtrace::resolve_usym(uint64_t addr) const
{
  // TODO
  std::ostringstream symbol;
  symbol << (void*)addr;
  return symbol.str();
}

void BPFtrace::sort_by_key(std::vector<SizedType> key_args,
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> &values_by_key)
{
  int arg_offset = 0;
  for (auto arg : key_args)
  {
    arg_offset += arg.size;
  }

  // Sort the key arguments in reverse order so the results are sorted by
  // the first argument first, then the second, etc.
  for (size_t i=key_args.size(); i-- > 0; )
  {
    auto arg = key_args.at(i);
    arg_offset -= arg.size;

    if (arg.type == Type::integer)
    {
      if (arg.size == 8)
      {
        std::stable_sort(values_by_key.begin(), values_by_key.end(), [&](auto &a, auto &b)
        {
          return *(uint64_t*)(a.first.data() + arg_offset) < *(uint64_t*)(b.first.data() + arg_offset);
        });
      }
      else
        abort();
    }
    else if (arg.type == Type::string)
    {
      std::stable_sort(values_by_key.begin(), values_by_key.end(), [&](auto &a, auto &b)
      {
        return strncmp((char*)(a.first.data() + arg_offset),
                       (char*)(b.first.data() + arg_offset),
                       STRING_SIZE) < 0;
      });
    }

    // Other types don't get sorted
  }
}

} // namespace bpftrace
