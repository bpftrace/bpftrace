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
#include <sys/prctl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef HAVE_BCC_ELF_FOREACH_SYM
#include <linux/elf.h>

#include "bcc_elf.h"
#endif

#include "bcc_syms.h"
#include "perf_reader.h"

#include "bpforc.h"
#include "bpftrace.h"
#include "attached_probe.h"
#include "printf.h"
#include "triggers.h"
#include "resolve_cgroupid.h"

extern char** environ;

namespace bpftrace {

DebugLevel bt_debug = DebugLevel::kNone;
bool bt_verbose = false;

BPFtrace::~BPFtrace()
{
  for (int pid : child_pids_)
  {
    // We don't care if waitpid returns any errors. We're just trying
    // to make a best effort here. It's not like we could recover from
    // an error.
    int status;
    waitpid(pid, &status, 0);
  }

  for (const auto& pair : pid_sym_)
  {
    if (pair.second)
      bcc_free_symcache(pair.second, pair.first);
  }

  if (ksyms_)
    bcc_free_symcache(ksyms_, -1);
}

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
    if (attach_point->need_expansion && has_wildcard(attach_point->func))
    {
      std::set<std::string> matches;
      switch (probetype(attach_point->provider))
      {
        case ProbeType::kprobe:
        case ProbeType::kretprobe:
          matches = find_wildcard_matches(attach_point->target,
                                          attach_point->func,
                                          "/sys/kernel/debug/tracing/available_filter_functions");
          break;
        case ProbeType::uprobe:
        case ProbeType::uretprobe:
        {
            auto symbol_stream = std::istringstream(extract_func_symbols_from_path(attach_point->target));
            matches = find_wildcard_matches("", attach_point->func, symbol_stream);
            break;
        }
        case ProbeType::tracepoint:
          matches = find_wildcard_matches(attach_point->target,
                                          attach_point->func,
                                          "/sys/kernel/debug/tracing/available_events");
          break;
        default:
          std::cerr << "Wildcard matches aren't available on probe type '"
                    << attach_point->provider << "'" << std::endl;
          return 1;
      }

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
      probe.ns = attach_point->ns;
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

std::set<std::string> BPFtrace::find_wildcard_matches(const std::string &prefix, const std::string &func, std::istream &symbol_name_stream)
{
  if (!has_wildcard(func))
    return std::set<std::string>({func});
  bool start_wildcard = func[0] == '*';
  bool end_wildcard = func[func.length() - 1] == '*';

  std::vector<std::string> tokens = split_string(func, '*');
  tokens.erase(std::remove(tokens.begin(), tokens.end(), ""), tokens.end());

  std::string line;
  std::set<std::string> matches;
  std::string full_prefix = prefix.empty() ? "" : (prefix + ":");
  while (std::getline(symbol_name_stream, line))
  {
    if (!full_prefix.empty()) {
      if (line.find(full_prefix, 0) != 0)
        continue;
      line = line.substr(full_prefix.length());
    }

    if (!wildcard_match(line, tokens, start_wildcard, end_wildcard))
      continue;

    // skip the ".part.N" kprobe variants, as they can't be traced:
    if (line.find(".part.") != std::string::npos)
      continue;

    matches.insert(line);
  }
  return matches;
}

std::set<std::string> BPFtrace::find_wildcard_matches(const std::string &prefix, const std::string &func, const std::string &file_name)
{
  if (!has_wildcard(func))
    return std::set<std::string>({func});
  std::ifstream file(file_name);
  if (file.fail())
  {
    throw std::runtime_error("Could not read symbols from \"" + file_name + "\", err=" + std::to_string(errno));
  }

  std::stringstream symbol_name_stream;
  std::string line;
  while (file >> line)
  {
    symbol_name_stream << line << std::endl;
  }

  file.close();

  return find_wildcard_matches(prefix, func, symbol_name_stream);
}

int BPFtrace::num_probes() const
{
  return special_probes_.size() + probes_.size();
}

void perf_event_printer(void *cb_cookie, void *data, int size __attribute__((unused)))
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
  else if (printf_id == asyncactionint(AsyncAction::cat))
  {
    uint64_t cat_id = (uint64_t)*(static_cast<uint64_t*>(data) + sizeof(uint64_t) / sizeof(uint64_t));
    auto filename = bpftrace->cat_args_[cat_id].c_str();
    cat_file(filename);
    return;
  }
  else if (printf_id == asyncactionint(AsyncAction::join))
  {
    uint64_t join_id = (uint64_t)*(static_cast<uint64_t*>(data) + sizeof(uint64_t) / sizeof(uint64_t));
    auto joinstr = bpftrace->join_args_[join_id].c_str();
    for (int i = 0; i < bpftrace->join_argnum_; i++) {
      auto *arg = arg_data + 2*sizeof(uint64_t) + i * bpftrace->join_argsize_;
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
    auto arg_values = bpftrace->get_arg_values(args, arg_data);

    char buffer [255];

    switch (args.size())
    {
      case 0:
        system(fmt);
        break;
      case 1:
        snprintf(buffer, 255, fmt, arg_values.at(0)->value());
        system(buffer);
        break;
      case 2:
        snprintf(buffer, 255, fmt, arg_values.at(0)->value(), arg_values.at(1)->value());
        system(buffer);
        break;
      case 3:
        snprintf(buffer, 255, fmt, arg_values.at(0)->value(), arg_values.at(1)->value(), arg_values.at(2)->value());
        system(buffer);
        break;
      case 4:
        snprintf(buffer, 255, fmt, arg_values.at(0)->value(), arg_values.at(1)->value(), arg_values.at(2)->value(),
          arg_values.at(3)->value());
        system(buffer);
        break;
      case 5:
        snprintf(buffer, 255, fmt, arg_values.at(0)->value(), arg_values.at(1)->value(), arg_values.at(2)->value(),
          arg_values.at(3)->value(), arg_values.at(4)->value());
        system(buffer);
        break;
      case 6:
        snprintf(buffer, 255, fmt, arg_values.at(0)->value(), arg_values.at(1)->value(), arg_values.at(2)->value(),
          arg_values.at(3)->value(), arg_values.at(4)->value(), arg_values.at(5)->value());
        system(buffer);
        break;
      default:
        std::cerr << "printf() can only take up to 7 arguments (" << args.size() << ") provided" << std::endl;
        abort();
    }

    return;
  }

  // printf
  auto fmt = std::get<0>(bpftrace->printf_args_[printf_id]).c_str();
  auto args = std::get<1>(bpftrace->printf_args_[printf_id]);
  auto arg_values = bpftrace->get_arg_values(args, arg_data);

  switch (args.size())
  {
    case 0:
      printf(fmt);
      break;
    case 1:
      printf(fmt, arg_values.at(0)->value());
      break;
    case 2:
      printf(fmt, arg_values.at(0)->value(), arg_values.at(1)->value());
      break;
    case 3:
      printf(fmt, arg_values.at(0)->value(), arg_values.at(1)->value(), arg_values.at(2)->value());
      break;
    case 4:
      printf(fmt, arg_values.at(0)->value(), arg_values.at(1)->value(), arg_values.at(2)->value(),
        arg_values.at(3)->value());
      break;
    case 5:
      printf(fmt, arg_values.at(0)->value(), arg_values.at(1)->value(), arg_values.at(2)->value(),
        arg_values.at(3)->value(), arg_values.at(4)->value());
      break;
    case 6:
      printf(fmt, arg_values.at(0)->value(), arg_values.at(1)->value(), arg_values.at(2)->value(),
        arg_values.at(3)->value(), arg_values.at(4)->value(), arg_values.at(5)->value());
      break;
    default:
      std::cerr << "printf() can only take up to 7 arguments (" << args.size() << ") provided" << std::endl;
      abort();
  }
}

std::vector<std::unique_ptr<IPrintable>> BPFtrace::get_arg_values(const std::vector<Field> &args, uint8_t* arg_data)
{
  std::vector<std::unique_ptr<IPrintable>> arg_values;

  for (auto arg : args)
  {
    switch (arg.type.type)
    {
      case Type::integer:
        switch (arg.type.size)
        {
          case 8:
            arg_values.push_back(
              std::make_unique<PrintableInt>(
                *reinterpret_cast<uint64_t*>(arg_data+arg.offset)));
            break;
          case 4:
            arg_values.push_back(
              std::make_unique<PrintableInt>(
                *reinterpret_cast<uint32_t*>(arg_data+arg.offset)));
            break;
          case 2:
            arg_values.push_back(
              std::make_unique<PrintableInt>(
                *reinterpret_cast<uint16_t*>(arg_data+arg.offset)));
            break;
          case 1:
            arg_values.push_back(
              std::make_unique<PrintableInt>(
                *reinterpret_cast<uint8_t*>(arg_data+arg.offset)));
            break;
          default:
            std::cerr << "get_arg_values: invalid integer size. 8, 4, 2 and byte supported. " << arg.type.size << "provided" << std::endl;
            abort();
        }
        break;
      case Type::string:
        arg_values.push_back(
          std::make_unique<PrintableCString>(
            reinterpret_cast<char *>(arg_data+arg.offset)));
        break;
      case Type::ksym:
        arg_values.push_back(
          std::make_unique<PrintableString>(
            resolve_ksym(*reinterpret_cast<uint64_t*>(arg_data+arg.offset))));
        break;
      case Type::usym:
        arg_values.push_back(
          std::make_unique<PrintableString>(
            resolve_usym(
              *reinterpret_cast<uint64_t*>(arg_data+arg.offset),
              *reinterpret_cast<uint64_t*>(arg_data+arg.offset + 8))));
        break;
      case Type::inet:
        arg_values.push_back(
          std::make_unique<PrintableString>(
            resolve_inet(
              *reinterpret_cast<int32_t*>(arg_data+arg.offset),
              reinterpret_cast<uint8_t*>(arg_data+arg.offset + 4))));
        break;
      case Type::username:
        arg_values.push_back(
          std::make_unique<PrintableString>(
            resolve_uid(
              *reinterpret_cast<uint64_t*>(arg_data+arg.offset))));
        break;
      case Type::probe:
        arg_values.push_back(
          std::make_unique<PrintableString>(
            resolve_probe(
              *reinterpret_cast<uint64_t*>(arg_data+arg.offset))));
        break;
      case Type::kstack:
        arg_values.push_back(
          std::make_unique<PrintableString>(
            get_stack(
              *reinterpret_cast<uint64_t*>(arg_data+arg.offset),
              false,
              arg.type.stack_type, 8)));
        break;
      case Type::ustack:
        arg_values.push_back(
          std::make_unique<PrintableString>(
            get_stack(
              *reinterpret_cast<uint64_t*>(arg_data+arg.offset),
              true,
              arg.type.stack_type, 8)));
        break;
      case Type::cast:
        if (arg.type.is_pointer) {
          arg_values.push_back(
            std::make_unique<PrintableInt>(
              *reinterpret_cast<uint64_t*>(arg_data+arg.offset)));
          break;
        }
        // fall through
      default:
        std::cerr << "invalid argument type" << std::endl;
        abort();
    }
  }

  return arg_values;
}

bool BPFtrace::is_numeric(std::string str)
{
  int i = 0;
  while (str[i]) {
    if (str[i] < '0' || str[i] > '9')
      return false;
    i++;
  }
  if (i == 0)
    return false;
  return true;
}

void BPFtrace::add_param(const std::string &param)
{
  params_.emplace_back(param);
}

std::string BPFtrace::get_param(size_t i)
{
  if (i > 0 && i < params_.size() + 1)
      return params_[i - 1];
  return "0";
}

void perf_event_lost(void *cb_cookie __attribute__((unused)), uint64_t lost)
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
  int wait_for_tracing_pipe;

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

  // Spawn a child process if we've been passed a command to run
  if (cmd_.size())
  {
    auto args = split_string(cmd_, ' ');
    args[0] = resolve_binary_path(args[0]);  // does path lookup on executable
    int pid = spawn_child(args, &wait_for_tracing_pipe);
    if (pid < 0)
    {
      std::cerr << "Failed to spawn child=" << cmd_ << std::endl;
      return pid;
    }

    child_pids_.emplace_back(pid);
    pid_ = pid;
  }

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

  // Kick the child to execute the command.
  if (cmd_.size())
  {
    char bf;

    int ret = write(wait_for_tracing_pipe, &bf, 1);
    if (ret < 0)
    {
      perror("unable to write to 'go' pipe");
      return ret;
    }

    close(wait_for_tracing_pipe);
  }

  if (bt_verbose)
    std::cerr << "Running..." << std::endl;

  poll_perf_events(epollfd);
  attached_probes_.clear();

  END_trigger();
  poll_perf_events(epollfd, true);
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

  std::vector<int> cpus = get_online_cpus();
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

void BPFtrace::poll_perf_events(int epollfd, bool drain)
{
  auto events = std::vector<struct epoll_event>(online_cpus_);
  while (true)
  {
    int ready = epoll_wait(epollfd, events.data(), online_cpus_, 100);

    // Return if either
    //   * epoll_wait has encountered an error (eg signal delivery)
    //   * There's no events left and we've been instructed to drain
    if (ready < 0 || (ready == 0 && drain))
    {
      return;
    }

    for (int i=0; i<ready; i++)
    {
      perf_reader_event_read((perf_reader*)events[i].data.ptr);
    }

    // If we are tracing a specific pid and it has exited, we should exit
    // as well b/c otherwise we'd be tracing nothing.
    //
    // Note that there technically is a race with a new process using the
    // same pid, but we're polling at 100ms and it would be unlikely that
    // the pids wrap around that fast.
    if (pid_ > 0 && !is_pid_alive(pid_))
    {
      return;
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
      if (map.type_.type == Type::hist || map.type_.type == Type::lhist)
        err = print_map_hist(map, top, div);
      else if (map.type_.type == Type::avg || map.type_.type == Type::stats)
          err = print_map_stats(map);
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
    if (map.type_.type == Type::hist || map.type_.type == Type::lhist ||
        map.type_.type == Type::stats || map.type_.type == Type::avg)
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

  int value_size = map.type_.size;
  if (map.type_.type == Type::count || map.type_.type == Type::sum ||
      map.type_.type == Type::min || map.type_.type == Type::max ||
      map.type_.type == Type::avg || map.type_.type == Type::hist ||
      map.type_.type == Type::lhist || map.type_.type == Type::stats )
    value_size *= ncpus_;
  std::vector<uint8_t> zero(value_size, 0);
  for (auto &key : keys)
  {
    int err = bpf_update_elem(map.mapfd_, key.data(), zero.data(), BPF_EXIST);

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
    if (map.type_.type == Type::count || map.type_.type == Type::sum ||
        map.type_.type == Type::min || map.type_.type == Type::max || map.type_.type == Type::integer)
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

  if (map.type_.type == Type::count || map.type_.type == Type::sum || map.type_.type == Type::integer)
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
  size_t total = values_by_key.size();
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

    if (map.type_.type == Type::kstack)
      std::cout << get_stack(*(uint64_t*)value.data(), false, map.type_.stack_type, 8);
    else if (map.type_.type == Type::ustack)
      std::cout << get_stack(*(uint64_t*)value.data(), true, map.type_.stack_type, 8);
    else if (map.type_.type == Type::ksym)
      std::cout << resolve_ksym(*(uintptr_t*)value.data());
    else if (map.type_.type == Type::usym)
      std::cout << resolve_usym(*(uintptr_t*)value.data(), *(uint64_t*)(value.data() + 8));
    else if (map.type_.type == Type::inet)
      std::cout << resolve_inet(*(int32_t*)value.data(), (uint8_t*)(value.data() + 4));
    else if (map.type_.type == Type::username)
      std::cout << resolve_uid(*(uint64_t*)(value.data())) << std::endl;
    else if (map.type_.type == Type::string)
      std::cout << value.data() << std::endl;
    else if (map.type_.type == Type::count || map.type_.type == Type::sum || map.type_.type == Type::integer)
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
  // stats() and avg() maps add an extra 8 bytes onto the end of their key for
  // storing the bucket number.

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
    uint64_t value = 0;

    if (count != 0)
      value = total / count;

    total_counts_by_key.push_back({map_elem.first, value});
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
    uint64_t average = 0;

    if (count != 0)
      average = total / count;

    if (map.type_.type == Type::stats)
      std::cout << "count " << count << ", average " <<  average << ", total " << total << std::endl;
    else
      std::cout << average << std::endl;
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
      header << "(..., 0)";
    }
    else if (i == 1)
    {
      header << "[0]";
    }
    else if (i == 2)
    {
      header << "[1]";
    }
    else
    {
      header << "[" << hist_index_label(i-2);
      header << ", " << hist_index_label(i-2+1) << ")";
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
      header << "(..., " << lhist_index_label(min) << ")";
    } else if (i == (buckets + 1)) {
      header << "[" << lhist_index_label(max) << ", ...)";
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

int BPFtrace::spawn_child(const std::vector<std::string>& args, int *notify_trace_start_pipe_fd)
{
  static const int maxargs = 256;
  char* argv[maxargs];
  int wait_for_tracing_pipe[2];

  // Convert vector of strings into raw array of C-strings for execve(2)
  int idx = 0;
  for (const auto& arg : args)
  {
    if (idx == maxargs - 1)
    {
      std::cerr << "Too many args passed into spawn_child (" << args.size()
        << " > " << maxargs - 1 << ")" << std::endl;
      return -1;
    }

    argv[idx] = const_cast<char*>(arg.c_str());
    ++idx;
  }
  argv[idx] = nullptr;  // must be null terminated

  if (pipe(wait_for_tracing_pipe) < 0)
  {
    perror("failed to create 'go' pipe");
    return -1;
  }

  // Fork and exec
  int ret = fork();
  if (ret == 0)
  {
    // Receive SIGTERM if parent dies
    //
    // Useful if user doesn't kill the bpftrace process group
    if (prctl(PR_SET_PDEATHSIG, SIGTERM))
      perror("prctl(PR_SET_PDEATHSIG)");

    // Closing the parent's end and wait until the
    // parent tells us to go. Set the child's end
    // to be closed on exec.
    close(wait_for_tracing_pipe[1]);
    fcntl(wait_for_tracing_pipe[0], F_SETFD, FD_CLOEXEC);

    char bf;

    ret = read(wait_for_tracing_pipe[0], &bf, 1);
    if (ret != 1)
    {
      perror("failed to read 'go' pipe");
      return -1;
    }

    if (execve(argv[0], argv, environ))
    {
      perror("execve");
      return -1;
    }
  }
  else if (ret > 0)
  {
    *notify_trace_start_pipe_fd = wait_for_tracing_pipe[1];
    return ret;
  }
  else
  {
    perror("fork");
    return -1;
  }

  return -1;  // silence end of control compiler warning
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
    sum += *(const uint64_t*)(value.data() + i*sizeof(uint64_t*));
  }
  return sum;
}

uint64_t BPFtrace::max_value(const std::vector<uint8_t> &value, int ncpus)
{
  uint64_t val, max = 0;
  for (int i=0; i<ncpus; i++)
  {
    val = *(const uint64_t*)(value.data() + i*sizeof(uint64_t*));
    if (val > max)
      max = val;
  }
  return max;
}

int64_t BPFtrace::min_value(const std::vector<uint8_t> &value, int ncpus)
{
  int64_t val, max = 0, retval;
  for (int i=0; i<ncpus; i++)
  {
    val = *(const int64_t*)(value.data() + i*sizeof(int64_t*));
    if (val > max)
      max = val;
  }

  /*
   * This is a hack really until the code generation for the min() function
   * is sorted out. The way it is currently implemented doesn't allow >
   * 32 bit quantities and also means we have to do gymnastics with the return
   * value owing to the way it is stored (i.e., 0xffffffff - val).
   */
  if (max == 0) /* If we have applied the zero() function */
    retval = max;
  else if ((0xffffffff - max) <= 0) /* A negative 32 bit value */
    retval =  0 - (max - 0xffffffff);
  else
    retval =  0xffffffff - max; /* A positive 32 bit value */

  return retval;
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

std::string BPFtrace::get_stack(uint64_t stackidpid, bool ustack, StackType stack_type, int indent)
{
  int32_t stackid = stackidpid & 0xffffffff;
  int pid = stackidpid >> 32;
  auto stack_trace = std::vector<uint64_t>(stack_type.limit);
  int err = bpf_lookup_elem(stackid_maps_[stack_type]->mapfd_, &stackid, stack_trace.data());
  if (err)
  {
    // ignore EFAULT errors: eg, kstack used but no kernel stack
    if (stackid != -EFAULT)
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
    std::string sym;
    if (!ustack)
      sym = resolve_ksym(addr, true);
    else
      sym = resolve_usym(addr, pid, true, stack_type.mode == StackMode::perf);

    switch (stack_type.mode) {
      case StackMode::bpftrace:
        stack << padding << sym << std::endl;
        break;
      case StackMode::perf:
        stack << "\t" << std::hex << addr << std::dec << " " << sym << std::endl;
        break;
      // TODO (mmarchini) enable -Wswitch-enum and disable -Wswitch-default
      default:
        abort();
    }
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

std::string BPFtrace::resolve_ksym(uintptr_t addr, bool show_offset)
{
  struct bcc_symbol ksym;
  std::ostringstream symbol;

  if (!ksyms_)
    ksyms_ = bcc_symcache_new(-1, nullptr);

  if (bcc_symcache_resolve(ksyms_, addr, &ksym) == 0)
  {
    symbol << ksym.name;
    if (show_offset)
      symbol << "+" << ksym.offset;
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
#ifdef HAVE_BCC_ELF_FOREACH_SYM
  bcc_symbol sym;
  int err = bcc_resolve_symname(path.c_str(), name.c_str(), 0, 0, nullptr, &sym);
  if (err)
    throw std::runtime_error("Could not resolve symbol: " + path + ":" + name);
  return sym.offset;
#else
  std::string call_str = std::string("objdump -tT ") + path + " | grep -w " + name;
  const char *call = call_str.c_str();
  auto result = exec_system(call);
  return read_address_from_output(result);
#endif
}

int add_symbol(const char *symname, uint64_t start, uint64_t size, void *payload) {
  auto syms = static_cast<std::ostringstream*>(payload);
  *syms << std::string(symname) << std::endl;
  return 0;
}

std::string BPFtrace::extract_func_symbols_from_path(const std::string &path)
{
#ifdef HAVE_BCC_ELF_FOREACH_SYM
  bcc_symbol_option symbol_option = {
    .use_debug_file = 1,
    .check_debug_file_crc = 1,
    .use_symbol_type = (1 << STT_FUNC) | (1 << STT_GNU_IFUNC)
  };

  std::ostringstream syms;
  int err = bcc_elf_foreach_sym(path.c_str(), add_symbol, &symbol_option, &syms);
  if (err)
    throw std::runtime_error("Could not list function symbols: " + path);

  return syms.str();
#else
  std::string call_str = std::string("objdump -tT ") + path +
    + " | " + "grep \"F .text\" | grep -oE '[^[:space:]]+$'";
  const char *call = call_str.c_str();
  return exec_system(call);
#endif
}

uint64_t BPFtrace::read_address_from_output(std::string output)
{
  std::string first_word = output.substr(0, output.find(" "));
  return std::stoull(first_word, 0, 16);
}


static std::string resolve_inetv4(uint8_t* inet) {
  char addr_cstr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, inet, addr_cstr, INET_ADDRSTRLEN);
  return std::string(addr_cstr);
}


static std::string resolve_inetv6(uint8_t* inet) {
  char addr_cstr[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, inet, addr_cstr, INET6_ADDRSTRLEN);
  return std::string(addr_cstr);
}


std::string BPFtrace::resolve_inet(int af, uint8_t* inet)
{
  std::string addrstr;
  switch (af) {
    case AF_INET:
      addrstr = resolve_inetv4(inet);
      break;
    case AF_INET6:
      addrstr = resolve_inetv6(inet);
      break;
    default:
    std::cerr << "ntop() got unsupported AF type: " << af << std::endl;
    addrstr = std::string("");
  }

  // TODO(mmarchini): handle inet_ntop errors
  return addrstr;
}

std::string BPFtrace::resolve_usym(uintptr_t addr, int pid, bool show_offset, bool show_module)
{
  struct bcc_symbol usym;
  std::ostringstream symbol;
  struct bcc_symbol_option symopts;
  void *psyms;

  // TODO: deal with these:
  symopts = {.use_debug_file = true,
	     .check_debug_file_crc = true,
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

  if (bcc_symcache_resolve(psyms, addr, &usym) == 0)
  {
    if (demangle_cpp_symbols)
      symbol << usym.demangle_name;
    else
      symbol << usym.name;
    if (show_offset)
      symbol << "+" << usym.offset;
    if (show_module)
      symbol << " (" << usym.module << ")";
  }
  else
  {
    symbol << (void*)addr;
    if (show_module)
      symbol << " ([unknown])";
  }

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
          return *(const uint64_t*)(a.first.data() + arg_offset) < *(const uint64_t*)(b.first.data() + arg_offset);
        });
      }
      else if (arg.size == 4)
      {
        std::stable_sort(values_by_key.begin(), values_by_key.end(), [&](auto &a, auto &b)
        {
          return *(const uint32_t*)(a.first.data() + arg_offset) < *(const uint32_t*)(b.first.data() + arg_offset);
        });
      }
      else
      {
        std::cerr << "invalid integer argument size. 4 or 8  expected, but " << arg.size << " provided" << std::endl;
        abort();
      }

    }
    else if (arg.type == Type::string)
    {
      std::stable_sort(values_by_key.begin(), values_by_key.end(), [&](auto &a, auto &b)
      {
        return strncmp((const char*)(a.first.data() + arg_offset),
                       (const char*)(b.first.data() + arg_offset),
                       STRING_SIZE) < 0;
      });
    }

    // Other types don't get sorted
  }
}

bool BPFtrace::is_pid_alive(int pid)
{
  char buf[256];
  int ret = snprintf(buf, sizeof(buf), "/proc/%d/status", pid);
  if (ret < 0)
  {
    throw std::runtime_error("failed to snprintf");
  }

  // Do a nonblocking wait on the pid just in case it's our child and it
  // has exited. We don't really care about any errors, we're just trying
  // to make a best effort.
  int status;
  waitpid(pid, &status, WNOHANG);

  int fd = open(buf, 0, O_RDONLY);
  if (fd < 0 && errno == ENOENT)
  {
    return false;
  }
  close(fd);

  return true;
}

} // namespace bpftrace
