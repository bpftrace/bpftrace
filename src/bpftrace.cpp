#include <assert.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <sstream>
#include <sys/epoll.h>
#include <time.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "bcc_syms.h"
#include "perf_reader.h"

#include "bpforc.h"
#include "bpftrace.h"
#include "attached_probe.h"
#include "triggers.h"
#include "resolve_cgroupid.h"

namespace bpftrace {

DebugLevel bt_debug = DebugLevel::kNone;
bool bt_verbose = false;

int BPFtrace::add_probe(ast::Probe &p)
{
  for (auto attach_point : *p.attach_points)
  {
    if (attach_point->provider == "BEGIN")
    {
      Probe probe;
      probe.path = "/proc/self/exe";
      probe.attach_point = "BEGIN_trigger";
      probe.type = probetype(attach_point->provider);
      probe.orig_name = p.name();
      probe.name = p.name();
      probe.loc = 0;
      probe.index = attach_point->index(probe.name) > 0 ?
          attach_point->index(probe.name) : p.index();
      special_probes_.push_back(probe);
      continue;
    }
    else if (attach_point->provider == "END")
    {
      Probe probe;
      probe.path = "/proc/self/exe";
      probe.attach_point = "END_trigger";
      probe.type = probetype(attach_point->provider);
      probe.orig_name = p.name();
      probe.name = p.name();
      probe.loc = 0;
      probe.index = attach_point->index(probe.name) > 0 ?
          attach_point->index(probe.name) : p.index();
      special_probes_.push_back(probe);
      continue;
    }

    std::vector<std::string> attach_funcs;
    if (attach_point->need_expansion && (
          attach_point->func.find("*") != std::string::npos ||
          attach_point->func.find("[") != std::string::npos &&
          attach_point->func.find("]") != std::string::npos))
    {
      std::string file_name;
      switch (probetype(attach_point->provider))
      {
        case ProbeType::kprobe:
        case ProbeType::kretprobe:
          file_name = "/sys/kernel/debug/tracing/available_filter_functions";
          break;
        case ProbeType::tracepoint:
          file_name = "/sys/kernel/debug/tracing/available_events";
          break;
        default:
          std::cerr << "Wildcard matches aren't available on probe type '"
                    << attach_point->provider << "'" << std::endl;
          return 1;
      }
      auto matches = find_wildcard_matches(attach_point->target,
                                           attach_point->func,
                                           file_name);
      attach_funcs.insert(attach_funcs.end(), matches.begin(), matches.end());
    }
    else
    {
      attach_funcs.push_back(attach_point->func);
    }

    for (auto func : attach_funcs)
    {
      Probe probe;
      probe.path = attach_point->target;
      probe.attach_point = func;
      probe.type = probetype(attach_point->provider);
      probe.orig_name = p.name();
      probe.name = attach_point->name(func);
      probe.freq = attach_point->freq;
      probe.loc = 0;
      probe.index = attach_point->index(func) > 0 ?
          attach_point->index(func) : p.index();
      probes_.push_back(probe);
    }
  }

  return 0;
}

std::set<std::string> BPFtrace::find_wildcard_matches(const std::string &prefix, const std::string &func, const std::string &file_name)
{
  // Turn glob into a regex
  auto regex_str = "(" + std::regex_replace(func, std::regex("\\*"), "[^\\s]*") + ")";
  if (prefix != "")
    regex_str = prefix + ":" + regex_str;
  regex_str = "^" + regex_str;
  std::regex func_regex(regex_str);
  std::smatch match;

  std::ifstream file(file_name);
  if (file.fail())
  {
    std::cerr << strerror(errno) << ": " << file_name << std::endl;
    return std::set<std::string>();
  }

  std::string line;
  std::set<std::string> matches;
  while (std::getline(file, line))
  {
    if (std::regex_search(line, match, func_regex))
    {
      assert(match.size() == 2);
      // skip the ".part.N" kprobe variants, as they can't be traced:
      if (std::strstr(match.str(1).c_str(), ".part.") == NULL)
        matches.insert(match[1]);
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
  auto arg_data = static_cast<uint8_t*>(data);
  int err;

  // async actions
  if (printf_id == asyncactionint(AsyncAction::exit))
  {
    err = bpftrace->print_maps();
    exit(err);
  }
  else if (printf_id == asyncactionint(AsyncAction::print))
  {
    std::string arg = (const char *)(static_cast<uint8_t*>(data) + sizeof(uint64_t) + 2 * sizeof(uint64_t));
    uint64_t top = (uint64_t)*(static_cast<uint64_t*>(data) + sizeof(uint64_t) / sizeof(uint64_t));
    uint64_t div = (uint64_t)*(static_cast<uint64_t*>(data) + (sizeof(uint64_t) + sizeof(uint64_t)) / sizeof(uint64_t));
    err = bpftrace->print_map_ident(arg, top, div);
    if (err)
      throw std::runtime_error("Could not print map with ident \"" + arg + "\", err=" + std::to_string(err));
    return;
  }
  else if (printf_id == asyncactionint(AsyncAction::clear))
  {
    std::string arg = (const char *)(arg_data+sizeof(uint64_t));
    err = bpftrace->clear_map_ident(arg);
    if (err)
      throw std::runtime_error("Could not clear map with ident \"" + arg + "\", err=" + std::to_string(err));
    return;
  }
  else if (printf_id == asyncactionint(AsyncAction::zero))
  {
    std::string arg = (const char *)(arg_data+sizeof(uint64_t));
    err = bpftrace->zero_map_ident(arg);
    if (err)
      throw std::runtime_error("Could not zero map with ident \"" + arg + "\", err=" + std::to_string(err));
    return;
  }
  else if (printf_id == asyncactionint(AsyncAction::time))
  {
    char timestr[STRING_SIZE];
    time_t t;
    struct tm *tmp;
    t = time(NULL);
    tmp = localtime(&t);
    if (tmp == NULL) {
      perror("localtime");
      return;
    }
    uint64_t time_id = (uint64_t)*(static_cast<uint64_t*>(data) + sizeof(uint64_t) / sizeof(uint64_t));
    auto fmt = bpftrace->time_args_[time_id].c_str();
    if (strftime(timestr, sizeof(timestr), fmt, tmp) == 0) {
      fprintf(stderr, "strftime returned 0");
      return;
    }
    printf("%s", timestr);
    return;
  }
  else if (printf_id == asyncactionint(AsyncAction::join))
  {
     const char *joinstr = " ";
     for (int i = 0; i < bpftrace->join_argnum_; i++) {
       auto *arg = arg_data+sizeof(uint64_t) + i * bpftrace->join_argsize_;
       if (arg[0] == 0)
         break;
       if (i)
         printf("%s", joinstr);
       printf("%s", arg);
     }
     printf("\n");
     return;
  }
  else if ( printf_id >= asyncactionint(AsyncAction::syscall))
  {
    auto id = printf_id - asyncactionint(AsyncAction::syscall);
    auto fmt = std::get<0>(bpftrace->system_args_[id]).c_str();
    auto args = std::get<1>(bpftrace->system_args_[id]);
    std::vector<uint64_t> arg_values = bpftrace->get_arg_values(args, arg_data);

    char buffer [255];

    switch (args.size())
    {
      case 0:
        system(fmt);
        break;
      case 1:
        snprintf(buffer, 255, fmt, arg_values.at(0));
        system(buffer);
        break;
      case 2:
        snprintf(buffer, 255, fmt, arg_values.at(0), arg_values.at(1));
        system(buffer);
        break;
      case 3:
        snprintf(buffer, 255, fmt, arg_values.at(0), arg_values.at(1), arg_values.at(2));
        system(buffer);
        break;
      case 4:
        snprintf(buffer, 255, fmt, arg_values.at(0), arg_values.at(1), arg_values.at(2),
          arg_values.at(3));
        system(buffer);
        break;
      case 5:
        snprintf(buffer, 255, fmt, arg_values.at(0), arg_values.at(1), arg_values.at(2),
          arg_values.at(3), arg_values.at(4));
        system(buffer);
        break;
     case 6:
        snprintf(buffer, 255, fmt, arg_values.at(0), arg_values.at(1), arg_values.at(2),
          arg_values.at(3), arg_values.at(4), arg_values.at(5));
        system(buffer);
        break;
      default:
        abort();
    }

    return;
  }

  // printf
  auto fmt = std::get<0>(bpftrace->printf_args_[printf_id]).c_str();
  auto args = std::get<1>(bpftrace->printf_args_[printf_id]);
  std::vector<uint64_t> arg_values = bpftrace->get_arg_values(args, arg_data);

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

std::vector<uint64_t> BPFtrace::get_arg_values(std::vector<Field> args, uint8_t* arg_data)
{
  std::vector<uint64_t> arg_values;
  std::vector<std::unique_ptr<char>> resolved_symbols;
  std::vector<std::unique_ptr<char>> resolved_usernames;

  char *name;
  for (auto arg : args)
  {
    switch (arg.type.type)
    {
      case Type::integer:
        switch (arg.type.size)
        {
          case 8:
            arg_values.push_back(*(uint64_t*)(arg_data+arg.offset));
            break;
          case 4:
            arg_values.push_back(*(uint32_t*)(arg_data+arg.offset));
            break;
          case 2:
            arg_values.push_back(*(uint16_t*)(arg_data+arg.offset));
            break;
          case 1:
            arg_values.push_back(*(uint8_t*)(arg_data+arg.offset));
            break;
          default:
            abort();
        }
        break;
      case Type::string:
        arg_values.push_back((uint64_t)(arg_data+arg.offset));
        break;
      case Type::sym:
        resolved_symbols.emplace_back(strdup(
              resolve_sym(*(uint64_t*)(arg_data+arg.offset)).c_str()));
        arg_values.push_back((uint64_t)resolved_symbols.back().get());
        break;
      case Type::usym:
        resolved_symbols.emplace_back(strdup(
              resolve_usym(*(uint64_t*)(arg_data+arg.offset), *(uint64_t*)(arg_data+arg.offset + 8)).c_str()));
        arg_values.push_back((uint64_t)resolved_symbols.back().get());
        break;
      case Type::inet:
        name = strdup(resolve_inet(*(uint64_t*)(arg_data+arg.offset), *(uint64_t*)(arg_data+arg.offset+8)).c_str());
        arg_values.push_back((uint64_t)name);
        break;
      case Type::username:
        resolved_usernames.emplace_back(strdup(
              resolve_uid(*(uint64_t*)(arg_data+arg.offset)).c_str()));
        arg_values.push_back((uint64_t)resolved_usernames.back().get());
        break;
      case Type::probe:
        name = strdup(resolve_probe(*(uint64_t*)(arg_data+arg.offset)).c_str());
        arg_values.push_back((uint64_t)name);
        break;
      case Type::stack:
        name = strdup(get_stack(*(uint64_t*)(arg_data+arg.offset), false, 8).c_str());
        arg_values.push_back((uint64_t)name);
        break;
      case Type::ustack:
        name = strdup(get_stack(*(uint64_t*)(arg_data+arg.offset), true, 8).c_str());
        arg_values.push_back((uint64_t)name);
        break;
      default:
        abort();
    }
  }

  return arg_values;
}

void perf_event_lost(void *cb_cookie, uint64_t lost)
{
  printf("Lost %lu events\n", lost);
}

std::unique_ptr<AttachedProbe> BPFtrace::attach_probe(Probe &probe, const BpfOrc &bpforc)
{
  // use the single-probe program if it exists (as is the case with wildcards
  // and the name builtin, which must be expanded into separate programs per
  // probe), else try to find a the program based on the original probe name
  // that includes wildcards.
  std::string index_str = "_" + std::to_string(probe.index);
  auto func = bpforc.sections_.find("s_" + probe.name + index_str);
  if (func == bpforc.sections_.end())
    func = bpforc.sections_.find("s_" + probe.orig_name + index_str);
  if (func == bpforc.sections_.end())
  {
    if (probe.name != probe.orig_name)
      std::cerr << "Code not generated for probe: " << probe.name << " from: " << probe.orig_name << std::endl;
    else
      std::cerr << "Code not generated for probe: " << probe.name << std::endl;
    return nullptr;
  }
  try
  {
    if (probe.type == ProbeType::usdt)
      return std::make_unique<AttachedProbe>(probe, func->second, pid_);
    else
      return std::make_unique<AttachedProbe>(probe, func->second);
  }
  catch (std::runtime_error &e)
  {
    std::cerr << e.what() << std::endl;
  }
  return nullptr;
}

int BPFtrace::run(std::unique_ptr<BpfOrc> bpforc)
{
  auto r_special_probes = special_probes_.rbegin();
  for (; r_special_probes != special_probes_.rend(); ++r_special_probes)
  {
    auto attached_probe = attach_probe(*r_special_probes, *bpforc.get());
    if (attached_probe == nullptr)
      return -1;
    special_attached_probes_.push_back(std::move(attached_probe));
  }

  int epollfd = setup_perf_events();
  if (epollfd < 0)
    return epollfd;

  BEGIN_trigger();

  // NOTE (mmarchini): Apparently the kernel fires kprobe_events in the reverse
  // order they were attached, so we insert them backwards to make sure blocks
  // are executed in the same order they were declared.
  auto r_probes = probes_.rbegin();
  for (; r_probes != probes_.rend(); ++r_probes)
  {
    auto attached_probe = attach_probe(*r_probes, *bpforc.get());
    if (attached_probe == nullptr)
      return -1;
    attached_probes_.push_back(std::move(attached_probe));
  }

  if (bt_verbose)
    std::cerr << "Running..." << std::endl;

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
  online_cpus_ = cpus.size();
  for (int cpu : cpus)
  {
    int page_cnt = 64;
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
  auto events = std::vector<struct epoll_event>(online_cpus_);
  while (true)
  {
    int ready = epoll_wait(epollfd, events.data(), online_cpus_, timeout);
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
    if (map.type_.type == Type::hist || map.type_.type == Type::lhist)
      err = print_map_hist(map, 0, 0);
    else if (map.type_.type == Type::avg || map.type_.type == Type::stats)
      err = print_map_stats(map);
    else
      err = print_map(map, 0, 0);
    std::cout << std::endl;

    if (err)
      return err;
  }

  return 0;
}

// print a map given an ident string
int BPFtrace::print_map_ident(const std::string &ident, uint32_t top, uint32_t div)
{
  int err = 0;
  for(auto &mapmap : maps_)
  {
    IMap &map = *mapmap.second.get();
    if (map.name_ == ident) {
      if (map.type_.type == Type::hist)
        err = print_map_hist(map, top, div);
      else
        err = print_map(map, top, div);
      return err;
    }
  }

  return -2;
}

// clear a map (delete all keys) given an ident string
int BPFtrace::clear_map_ident(const std::string &ident)
{
  int err = 0;
  for(auto &mapmap : maps_)
  {
    IMap &map = *mapmap.second.get();
    if (map.name_ == ident) {
        err = clear_map(map);
      return err;
    }
  }

  return -2;
}

// zero a map (set all keys to zero) given an ident string
int BPFtrace::zero_map_ident(const std::string &ident)
{
  int err = 0;
  for(auto &mapmap : maps_)
  {
    IMap &map = *mapmap.second.get();
    if (map.name_ == ident) {
        err = zero_map(map);
      return err;
    }
  }

  return -2;
}

// clear a map
int BPFtrace::clear_map(IMap &map)
{
  std::vector<uint8_t> old_key;
  try
  {
    if (map.type_.type == Type::hist)
      // hist maps have 8 extra bytes for the bucket number
      old_key = find_empty_key(map, map.key_.size() + 8);
    else
      old_key = find_empty_key(map, map.key_.size());
  }
  catch (std::runtime_error &e)
  {
    std::cerr << "Error getting key for map '" << map.name_ << "': "
              << e.what() << std::endl;
    return -2;
  }
  auto key(old_key);

  // snapshot keys, then operate on them
  std::vector<std::vector<uint8_t>> keys;
  while (bpf_get_next_key(map.mapfd_, old_key.data(), key.data()) == 0)
  {
    keys.push_back(key);
    old_key = key;
  }

  for (auto &key : keys)
  {
    int err = bpf_delete_elem(map.mapfd_, key.data());
    if (err)
    {
      std::cerr << "Error looking up elem: " << err << std::endl;
      return -1;
    }
  }

  return 0;
}

// zero a map
int BPFtrace::zero_map(IMap &map)
{
  std::vector<uint8_t> old_key;
  try
  {
    if (map.type_.type == Type::hist)
      // hist maps have 8 extra bytes for the bucket number
      old_key = find_empty_key(map, map.key_.size() + 8);
    else
      old_key = find_empty_key(map, map.key_.size());
  }
  catch (std::runtime_error &e)
  {
    std::cerr << "Error getting key for map '" << map.name_ << "': "
              << e.what() << std::endl;
    return -2;
  }
  auto key(old_key);

  // snapshot keys, then operate on them
  std::vector<std::vector<uint8_t>> keys;
  while (bpf_get_next_key(map.mapfd_, old_key.data(), key.data()) == 0)
  {
    keys.push_back(key);
    old_key = key;
  }

  uint64_t zero = 0;
  for (auto &key : keys)
  {
    int err = bpf_update_elem(map.mapfd_, key.data(), &zero, BPF_EXIST);

    if (err)
    {
      std::cerr << "Error looking up elem: " << err << std::endl;
      return -1;
    }
  }

  return 0;
}

int BPFtrace::print_map(IMap &map, uint32_t top, uint32_t div)
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
    if (map.type_.type == Type::count ||
        map.type_.type == Type::sum || map.type_.type == Type::min || map.type_.type == Type::max)
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

  if (map.type_.type == Type::count || map.type_.type == Type::sum)
  {
    std::sort(values_by_key.begin(), values_by_key.end(), [&](auto &a, auto &b)
    {
      return reduce_value(a.second, ncpus_) < reduce_value(b.second, ncpus_);
    });
  }
  else if (map.type_.type == Type::min)
  {
    std::sort(values_by_key.begin(), values_by_key.end(), [&](auto &a, auto &b)
    {
      return min_value(a.second, ncpus_) < min_value(b.second, ncpus_);
    });
  }
  else if (map.type_.type == Type::max)
  {
    std::sort(values_by_key.begin(), values_by_key.end(), [&](auto &a, auto &b)
    {
      return max_value(a.second, ncpus_) < max_value(b.second, ncpus_);
    });
  }
  else
  {
    sort_by_key(map.key_.args_, values_by_key);
  };

  if (div == 0)
    div = 1;
  uint32_t i = 0;
  int total = values_by_key.size();
  for (auto &pair : values_by_key)
  {
    auto key = pair.first;
    auto value = pair.second;

    if (top)
    {
      if (total > top && i++ < (total - top))
        continue;
    }

    std::cout << map.name_ << map.key_.argument_value_list(*this, key) << ": ";

    if (map.type_.type == Type::stack)
      std::cout << get_stack(*(uint64_t*)value.data(), false, 8);
    else if (map.type_.type == Type::ustack)
      std::cout << get_stack(*(uint64_t*)value.data(), true, 8);
    else if (map.type_.type == Type::sym)
      std::cout << resolve_sym(*(uintptr_t*)value.data());
    else if (map.type_.type == Type::usym)
      std::cout << resolve_usym(*(uintptr_t*)value.data(), *(uint64_t*)(value.data() + 8));
    else if (map.type_.type == Type::inet)
      std::cout << resolve_inet(*(uintptr_t*)value.data(), *(uint64_t*)(value.data() + 8));
    else if (map.type_.type == Type::username)
      std::cout << resolve_uid(*(uint64_t*)(value.data())) << std::endl;
    else if (map.type_.type == Type::string)
      std::cout << value.data() << std::endl;
    else if (map.type_.type == Type::count || map.type_.type == Type::sum)
      std::cout << reduce_value(value, ncpus_) / div << std::endl;
    else if (map.type_.type == Type::min)
      std::cout << min_value(value, ncpus_) / div << std::endl;
    else if (map.type_.type == Type::max)
      std::cout << max_value(value, ncpus_) / div << std::endl;
    else if (map.type_.type == Type::probe)
      std::cout << resolve_probe(*(uint64_t*)value.data()) << std::endl;
    else
      std::cout << *(int64_t*)value.data() / div << std::endl;
  }
  if (i == 0)
    std::cout << std::endl;

  return 0;
}

int BPFtrace::print_map_hist(IMap &map, uint32_t top, uint32_t div)
{
  // A hist-map adds an extra 8 bytes onto the end of its key for storing
  // the bucket number.
  // e.g. A map defined as: @x[1, 2] = @hist(3);
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
      if (map.type_.type == Type::hist)
        values_by_key[key_prefix] = std::vector<uint64_t>(65);
      else
        values_by_key[key_prefix] = std::vector<uint64_t>(1002);
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

  if (div == 0)
    div = 1;
  uint32_t i = 0;
  for (auto &key_count : total_counts_by_key)
  {
    auto &key = key_count.first;
    auto &value = values_by_key[key];

    if (top)
    {
      if (i++ < (values_by_key.size() - top))
        continue;
    }

    std::cout << map.name_ << map.key_.argument_value_list(*this, key) << ": " << std::endl;

    if (map.type_.type == Type::hist)
      print_hist(value, div);
    else
      print_lhist(value, map.lqmin, map.lqmax, map.lqstep);

    std::cout << std::endl;
  }

  return 0;
}

int BPFtrace::print_map_stats(IMap &map)
{
  // A hist-map adds an extra 8 bytes onto the end of its key for storing
  // the bucket number.

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
      values_by_key[key_prefix] = std::vector<uint64_t>(2);
    }
    values_by_key[key_prefix].at(bucket) = reduce_value(value, ncpus_);

    old_key = key;
  }

  // Sort based on sum of counts in all buckets
  std::vector<std::pair<std::vector<uint8_t>, uint64_t>> total_counts_by_key;
  for (auto &map_elem : values_by_key)
  {
    assert(map_elem.second.size() == 2);
    uint64_t count = map_elem.second.at(0);
    uint64_t total = map_elem.second.at(1);
    assert(count != 0);
    total_counts_by_key.push_back({map_elem.first, total / count});
  }
  std::sort(total_counts_by_key.begin(), total_counts_by_key.end(), [&](auto &a, auto &b)
  {
    return a.second < b.second;
  });

  for (auto &key_count : total_counts_by_key)
  {
    auto &key = key_count.first;
    auto &value = values_by_key[key];
    std::cout << map.name_ << map.key_.argument_value_list(*this, key) << ": ";

    uint64_t count = value.at(0);
    uint64_t total = value.at(1);

    if (map.type_.type == Type::stats)
      std::cout << "count " << count << ", average " << total / count << ", total " << total << std::endl;
    else
      std::cout << total / count << std::endl;
  }

  std::cout << std::endl;

  return 0;
}

int BPFtrace::print_hist(const std::vector<uint64_t> &values, uint32_t div) const
{
  int min_index = -1;
  int max_index = -1;
  int max_value = 0;

  for (size_t i = 0; i < values.size(); i++)
  {
    int v = values.at(i);
    if (v > 0) {
      if (min_index == -1)
        min_index = i;
      max_index = i;
    }
    if (v > max_value)
      max_value = v;
  }

  if (max_index == -1)
    return 0;

  for (int i = min_index; i <= max_index; i++)
  {
    std::ostringstream header;
    if (i == 0)
    {
      header << "[0, 1]";
    }
    else
    {
      header << "[" << hist_index_label(i);
      header << ", " << hist_index_label(i+1) << ")";
    }

    int max_width = 52;
    int bar_width = values.at(i)/(float)max_value*max_width;
    std::string bar(bar_width, '@');

    std::cout << std::setw(16) << std::left << header.str()
              << std::setw(8) << std::right << (values.at(i) / div)
              << " |" << std::setw(max_width) << std::left << bar << "|"
              << std::endl;
  }

  return 0;
}

int BPFtrace::print_lhist(const std::vector<uint64_t> &values, int min, int max, int step) const
{
  int max_index = -1;
  int max_value = 0;
  int buckets = (max - min) / step;	// excluding lt and gt buckets

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

  std::ostringstream lt;
  lt << "(...," << lhist_index_label(min) << "]";
  std::ostringstream gt;

  // trim empty values
  int start_value = -1;
  int end_value = 0;

  for (int i = 0; i <= buckets + 1; i++)
  {
    if (values.at(i) > 0) {
      if (start_value == -1) {
        start_value = i;
      }
      end_value = i;
    }
  }

  if (start_value == -1) {
    start_value = 0;
  }

  for (int i = start_value; i <= end_value; i++)
  {
    int max_width = 52;
    int bar_width = values.at(i)/(float)max_value*max_width;
    std::ostringstream header;
    if (i == 0) {
      header << "(...," << lhist_index_label(min) << "]";
    } else if (i == (buckets + 1)) {
      header << "[" << lhist_index_label(max) << ",...)";
    } else {
      header << "[" << lhist_index_label((i - 1) * step + min);
      header << ", " << lhist_index_label(i * step + min) << ")";
    }

    std::string bar(bar_width, '@');

    std::cout << std::setw(16) << std::left << header.str()
              << std::setw(8) << std::right << values.at(i)
              << " |" << std::setw(max_width) << std::left << bar << "|"
              << std::endl;
  }

  return 0;
}

std::string BPFtrace::hist_index_label(int power)
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
    suffix = 'K';
    power -= 10;
  }

  std::ostringstream label;
  label << (1<<power);
  if (suffix)
    label << suffix;
  return label.str();
}

std::string BPFtrace::lhist_index_label(int number)
{
  int kilo = 1024;
  int mega = 1048576;

  std::ostringstream label;

  if (number == 0)
  {
    label << number;
  }
  else if (number % mega == 0)
  {
    label << number / mega << 'M';
  }
  else if (number % kilo == 0)
  {
    label << number / kilo << 'K';
  }
  else
  {
    label << number;
  }

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

uint64_t BPFtrace::max_value(const std::vector<uint8_t> &value, int ncpus)
{
  uint64_t val, max = 0;
  for (int i=0; i<ncpus; i++)
  {
    val = *(uint64_t*)(value.data() + i*sizeof(uint64_t*));
    if (val > max)
      max = val;
  }
  return max;
}

uint64_t BPFtrace::min_value(const std::vector<uint8_t> &value, int ncpus)
{
  uint64_t val, max = 0;
  for (int i=0; i<ncpus; i++)
  {
    val = *(uint64_t*)(value.data() + i*sizeof(uint64_t*));
    if (val > max)
      max = val;
  }
  return (0xffffffff - max);
}

std::vector<uint8_t> BPFtrace::find_empty_key(IMap &map, size_t size) const
{
  if (size == 0) size = 8;
  auto key = std::vector<uint8_t>(size);
  int value_size = map.type_.size;
  if (map.type_.type == Type::count || map.type_.type == Type::hist ||
      map.type_.type == Type::sum || map.type_.type == Type::min ||
      map.type_.type == Type::max || map.type_.type == Type::avg ||
      map.type_.type == Type::stats || map.type_.type == Type::lhist)
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

std::string BPFtrace::get_stack(uint64_t stackidpid, bool ustack, int indent)
{
  uint32_t stackid = stackidpid & 0xffffffff;
  int pid = stackidpid >> 32;
  auto stack_trace = std::vector<uint64_t>(MAX_STACK_SIZE);
  int err = bpf_lookup_elem(stackid_map_->mapfd_, &stackid, stack_trace.data());
  if (err)
  {
    std::cerr << "Error looking up stack id " << stackid << " (pid " << pid << "): " << err << std::endl;
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
      stack << padding << resolve_usym(addr, pid, true) << std::endl;
  }

  return stack.str();
}

std::string BPFtrace::resolve_uid(uintptr_t addr)
{
  std::string file_name = "/etc/passwd";
  std::string uid = std::to_string(addr);
  std::string username = "";

  std::ifstream file(file_name);
  if (file.fail())
  {
    std::cerr << strerror(errno) << ": " << file_name << std::endl;
    return username;
  }

  std::string line;
  bool found = false;

  while (std::getline(file, line) && !found)
  {
    auto fields = split_string(line, ':');

    if (fields[2] == uid)
    {
      found = true;
      username = fields[0];
    }
  }

  file.close();

  return username;
}

std::vector<std::string> BPFtrace::split_string(std::string &str, char split_by)
{
  std::vector<std::string> elems;
  std::stringstream ss(str);
  std::string value;
  while(std::getline(ss, value, split_by)) {
      elems.push_back(value);
  }
  return elems;
}

std::string BPFtrace::resolve_sym(uintptr_t addr, bool show_offset)
{
  struct bcc_symbol sym;
  std::ostringstream symbol;

  if (ksyms_.resolve_addr(addr, &sym))
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

uint64_t BPFtrace::resolve_kname(const std::string &name)
{
  uint64_t addr = 0;
  std::string file_name = "/proc/kallsyms";

  std::ifstream file(file_name);
  if (file.fail())
  {
    std::cerr << strerror(errno) << ": " << file_name << std::endl;
    return addr;
  }

  std::string line;

  std::string search = "\\b";
  search += name;
  std::regex e (search + "\\b");
  std::smatch match;

  while (std::getline(file, line) && addr == 0)
  {
    auto found = std::regex_search (line, match, e);

    if (found)
    {
      addr = read_address_from_output(line);
    }
  }

  file.close();

  return addr;
}

uint64_t BPFtrace::resolve_cgroupid(const std::string &path)
{
  return bpftrace_linux::resolve_cgroupid(path);
}

uint64_t BPFtrace::resolve_uname(const std::string &name, const std::string &path)
{
  uint64_t addr = 0;

  // TODO: switch from objdump to library call, perhaps bcc_resolve_symname()
  std::string call_str = std::string("objdump -tT ") + path + " | grep -w " + name;
  const char *call = call_str.c_str();
  auto result = exec_system(call);
  addr = read_address_from_output(result);

  return addr;
}

std::string BPFtrace::exec_system(const char* cmd)
{
  std::array<char, 128> buffer;
  std::string result;
  std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
  if (!pipe) throw std::runtime_error("popen() failed!");
  while (!feof(pipe.get())) {
    if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
      result += buffer.data();
  }
  return result;
}

uint64_t BPFtrace::read_address_from_output(std::string output)
{
  std::string first_word = output.substr(0, output.find(" "));
  return std::stoull(first_word, 0, 16);
}

std::string BPFtrace::resolve_inet(int af, uint64_t inet)
{

  // FIXME ipv6 is a 128 bit type as an array, how to pass as argument?
  if(af != AF_INET)
  {
    std::cerr << "ntop() currently only supports AF_INET (IPv4); IPv6 will be supported in the future." << std::endl;
    return std::string("");
  }
  char addr_cstr[INET_ADDRSTRLEN];
  inet_ntop(af, &inet, addr_cstr, INET_ADDRSTRLEN);
  std::string addrstr(addr_cstr);
  return addrstr;
}

std::string BPFtrace::resolve_usym(uintptr_t addr, int pid, bool show_offset)
{
  struct bcc_symbol sym;
  std::ostringstream symbol;
  struct bcc_symbol_option symopts;
  void *psyms;

  // TODO: deal with these:
  symopts = {.use_debug_file = false,
	     .check_debug_file_crc = false,
	     .use_symbol_type = BCC_SYM_ALL_TYPES};

  if (pid_sym_.find(pid) == pid_sym_.end())
  {
    // not cached, create new ProcSyms cache
    psyms = bcc_symcache_new(pid, &symopts);
    pid_sym_[pid] = psyms;
  }
  else
  {
    psyms = pid_sym_[pid];
  }

  if (((ProcSyms *)psyms)->resolve_addr(addr, &sym))
  {
    symbol << sym.name;
    if (show_offset)
      symbol << "+" << sym.offset;
  }
  else
  {
    symbol << (void*)addr;
  }

  // TODO: deal with process exit and clearing its psyms entry

  return symbol.str();
}

std::string BPFtrace::resolve_probe(uint64_t probe_id)
{
  assert(probe_id < probe_ids_.size());
  return probe_ids_[probe_id];
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
      else if (arg.size == 4)
      {
        std::stable_sort(values_by_key.begin(), values_by_key.end(), [&](auto &a, auto &b)
        {
          return *(uint32_t*)(a.first.data() + arg_offset) < *(uint32_t*)(b.first.data() + arg_offset);
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
