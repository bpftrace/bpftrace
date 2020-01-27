#include <assert.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <sys/epoll.h>
#include <time.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
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
#include "utils.h"

extern char** environ;

namespace bpftrace {

DebugLevel bt_debug = DebugLevel::kNone;
bool bt_verbose = false;
volatile sig_atomic_t BPFtrace::exitsig_recv = false;
constexpr char CHILD_EXIT_QUIETLY = '\0';
constexpr char CHILD_GO = 'g';

int format(char * s, size_t n, const char * fmt, std::vector<std::unique_ptr<IPrintable>> &args) {
  int ret = -1;
  switch(args.size()) {
    case 0:
      ret = snprintf(s, n, "%s", fmt);
      break;
    case 1:
      ret = snprintf(s, n, fmt, args.at(0)->value());
      break;
    case 2:
      ret = snprintf(s, n, fmt, args.at(0)->value(), args.at(1)->value());
      break;
    case 3:
      ret = snprintf(s, n, fmt, args.at(0)->value(), args.at(1)->value(), args.at(2)->value());
      break;
    case 4:
      ret = snprintf(s, n, fmt, args.at(0)->value(), args.at(1)->value(), args.at(2)->value(), args.at(3)->value());
      break;
    case 5:
      ret = snprintf(s, n, fmt, args.at(0)->value(), args.at(1)->value(), args.at(2)->value(),
        args.at(3)->value(), args.at(4)->value());
      break;
    case 6:
      ret = snprintf(s, n, fmt, args.at(0)->value(), args.at(1)->value(), args.at(2)->value(),
        args.at(3)->value(), args.at(4)->value(), args.at(5)->value());
      break;
    default:
      std::cerr << "format() can only take up to 7 arguments (" << args.size() << ") provided" << std::endl;
      abort();
  }
  if (ret < 0 && errno != 0) {
    std::cerr << "format() error occurred: " << std::strerror(errno) << std::endl;
    abort();
  }
  return ret;
}

BPFtrace::~BPFtrace()
{
  kill_child();
  if (child_pid() != 0)
  {
    // We don't care if waitpid returns any errors. We're just trying
    // to make a best effort here. It's not like we could recover from
    // an error.
    int status;
    waitpid(child_pid(), &status, 0);
  }

  for (const auto& pair : exe_sym_)
  {
    if (pair.second.second)
      bcc_free_symcache(pair.second.second, pair.second.first);
  }

  if (ksyms_)
    bcc_free_symcache(ksyms_, -1);
}

int BPFtrace::add_probe(ast::Probe &p)
{
  for (auto attach_point : *p.attach_points)
  {
    if (attach_point->provider == "BEGIN" || attach_point->provider == "END")
    {
      Probe probe;
      probe.path = "/proc/self/exe";
      probe.attach_point = attach_point->provider + "_trigger";
      probe.type = probetype(attach_point->provider);
      probe.log_size = log_size_;
      probe.orig_name = p.name();
      probe.name = p.name();
      probe.loc = 0;
      probe.pid = getpid();
      probe.index = attach_point->index(probe.name) > 0 ?
          attach_point->index(probe.name) : p.index();
      special_probes_.push_back(probe);
      continue;
    }

    std::vector<std::string> attach_funcs;
    bool underspecified_usdt_probe = (probetype(attach_point->provider) == ProbeType::usdt  && attach_point->ns.empty());
    if (attach_point->need_expansion && (has_wildcard(attach_point->func) || underspecified_usdt_probe))
    {
      std::set<std::string> matches;
      try
      {
        matches = find_wildcard_matches(*attach_point);
      }
      catch (const WildcardException &e)
      {
        std::cerr << e.what() << std::endl;
        return 1;
      }
      attach_funcs.insert(attach_funcs.end(), matches.begin(), matches.end());
    }
    else
    {
      if (probetype(attach_point->provider) == ProbeType::usdt && !attach_point->ns.empty())
        attach_funcs.push_back(attach_point->ns + ":" + attach_point->func);
      else
        attach_funcs.push_back(attach_point->func);
    }

    for (auto func_ : attach_funcs)
    {
      std::string full_func_id = func_;
      std::string func_id = func_;

      // USDT probes must specify both a provider and a function name for full id
      // So we will extract out the provider namespace to get just the function name
      if (probetype(attach_point->provider) == ProbeType::usdt )
      {
        std::string ns = func_id.substr(0, func_id.find(":"));
        func_id.erase(0, func_id.find(":")+1);
        // Set attach_point ns to be a resolved namespace in case of wildcard
        attach_point->ns = ns;
        // Set the function name to be a resolved function id in case of wildcard
        attach_point->func = func_id;
      }

      Probe probe;
      probe.path = attach_point->target;
      probe.attach_point = func_id;
      probe.type = probetype(attach_point->provider);
      probe.log_size = log_size_;
      probe.orig_name = p.name();
      probe.ns = attach_point->ns;
      probe.name = attach_point->name(func_id);
      probe.freq = attach_point->freq;
      probe.address = attach_point->address;
      probe.func_offset = attach_point->func_offset;
      probe.loc = 0;
      probe.index = attach_point->index(full_func_id) > 0 ?
          attach_point->index(full_func_id) : p.index();
      probe.addr = attach_point->addr;
      probe.len = attach_point->len;
      probe.mode = attach_point->mode;
      probes_.push_back(probe);
    }
  }

  return 0;
}

std::set<std::string> BPFtrace::find_wildcard_matches(
    const ast::AttachPoint &attach_point) const
{
  std::unique_ptr<std::istream> symbol_stream;
  std::string prefix, func;

  switch (probetype(attach_point.provider))
  {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
    {
      symbol_stream = get_symbols_from_file(
          "/sys/kernel/debug/tracing/available_filter_functions");
      prefix = "";
      func = attach_point.func;
      break;
    }
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    {
      symbol_stream = std::make_unique<std::istringstream>(
          extract_func_symbols_from_path(attach_point.target));
      prefix = "";
      func = attach_point.func;
      break;
    }
    case ProbeType::tracepoint:
    {
      symbol_stream = get_symbols_from_file(
          "/sys/kernel/debug/tracing/available_events");
      prefix = attach_point.target;
      func = attach_point.func;
      break;
    }
    case ProbeType::usdt:
    {
      symbol_stream = get_symbols_from_usdt(pid_, attach_point.target);
      prefix = "";
      if (attach_point.ns == "")
        func = "*:" + attach_point.func;
      else
        func = attach_point.ns + ":" + attach_point.func;
      break;
    }
    default:
    {
      throw WildcardException("Wildcard matches aren't available on probe type '"
          + attach_point.provider + "'");
    }
  }

  return find_wildcard_matches(prefix, func, *symbol_stream);
}

/*
 * Finds all matches of func in the provided input stream.
 *
 * If an optional prefix is provided, lines must start with it to count as a
 * match, but the prefix is stripped from entries in the result set.
 * Wildcard tokens ("*") are accepted in func.
 */
std::set<std::string> BPFtrace::find_wildcard_matches(
    const std::string &prefix,
    const std::string &func,
    std::istream &symbol_stream) const
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
  while (std::getline(symbol_stream, line))
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

std::unique_ptr<std::istream> BPFtrace::get_symbols_from_file(const std::string &path) const
{
  auto file = std::make_unique<std::ifstream>(path);
  if (file->fail())
  {
    throw std::runtime_error("Could not read symbols from " + path +
                             ": " + strerror(errno));
  }

  return file;
}

std::unique_ptr<std::istream> BPFtrace::get_symbols_from_usdt(
    int pid,
    const std::string &target) const
{
  std::string probes;
  usdt_probe_list usdt_probes;

  if (pid > 0)
    usdt_probes = USDTHelper::probes_for_pid(pid);
  else
    usdt_probes = USDTHelper::probes_for_path(target);

  for (auto const& usdt_probe : usdt_probes)
  {
    std::string path     = std::get<USDT_PATH_INDEX>(usdt_probe);
    std::string provider = std::get<USDT_PROVIDER_INDEX>(usdt_probe);
    std::string fname    = std::get<USDT_FNAME_INDEX>(usdt_probe);
    probes += provider + ":" + fname + "\n";
  }

  return std::make_unique<std::istringstream>(probes);
}

int BPFtrace::num_probes() const
{
  return special_probes_.size() + probes_.size();
}

void BPFtrace::kill_child()
{
  if (child_pid() == 0)
    return;

  if (child_running_) {
    kill(child_pid(), SIGTERM);
  } else {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
    // We need to disable this warning for some GCC/libc combinations despite
    // using the void cast: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=66425
    (void)write(child_start_pipe_, &CHILD_EXIT_QUIETLY, 1);
#pragma GCC diagnostic pop
    close(child_start_pipe_);
  }
}

void BPFtrace::request_finalize()
{
  finalize_ = true;
  attached_probes_.clear();
  kill_child();

}

void perf_event_printer(void *cb_cookie, void *data, int size __attribute__((unused)))
{
  auto bpftrace = static_cast<BPFtrace*>(cb_cookie);
  auto printf_id = *static_cast<uint64_t*>(data);
  auto arg_data = static_cast<uint8_t*>(data);
  int err;

  // Ignore the remaining events if perf_event_printer is called during finalization
  // stage (exit() builtin has been called)
  if (bpftrace->finalize_)
    return;

  if (bpftrace->exitsig_recv)
  {
    bpftrace->request_finalize();
    return;
  }

  // async actions
  if (printf_id == asyncactionint(AsyncAction::exit))
  {
    bpftrace->request_finalize();
    return;
  }
  else if (printf_id == asyncactionint(AsyncAction::print))
  {
    std::string arg = (const char *)(static_cast<uint8_t*>(data) + sizeof(uint64_t) + 2 * sizeof(uint64_t));
    uint64_t top = (uint64_t) * (static_cast<uint64_t *>(data) + 1);
    uint64_t div = (uint64_t) * (static_cast<uint64_t *>(data) + 2);
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
      std::cerr << "localtime: " << strerror(errno) << std::endl;
      return;
    }
    uint64_t time_id = (uint64_t) * (static_cast<uint64_t *>(data) + 1);
    auto fmt = bpftrace->time_args_[time_id].c_str();
    if (strftime(timestr, sizeof(timestr), fmt, tmp) == 0) {
      std::cerr << "strftime returned 0" << std::endl;
      return;
    }
    bpftrace->out_->message(MessageType::time, timestr, false);
    return;
  }
  else if (printf_id == asyncactionint(AsyncAction::join))
  {
    uint64_t join_id = (uint64_t) * (static_cast<uint64_t *>(data) + 1);
    auto delim = bpftrace->join_args_[join_id].c_str();
    std::stringstream joined;
    for (unsigned int i = 0; i < bpftrace->join_argnum_; i++) {
      auto *arg = arg_data + 2*sizeof(uint64_t) + i * bpftrace->join_argsize_;
      if (arg[0] == 0)
        break;
      if (i)
        joined << delim;
      joined << arg;
    }
    bpftrace->out_->message(MessageType::join, joined.str());
    return;
  }
  else if ( printf_id >= asyncactionint(AsyncAction::syscall) &&
            printf_id < asyncactionint(AsyncAction::syscall) + RESERVED_IDS_PER_ASYNCACTION)
  {
    if (bpftrace->safe_mode_)
    {
      std::cerr << "syscall() not allowed in safe mode" << std::endl;
      abort();
    }

    auto id = printf_id - asyncactionint(AsyncAction::syscall);
    auto fmt = std::get<0>(bpftrace->system_args_[id]).c_str();
    auto args = std::get<1>(bpftrace->system_args_[id]);
    auto arg_values = bpftrace->get_arg_values(args, arg_data);

    const int BUFSIZE = 512;
    char buffer[BUFSIZE];
    int size = format(buffer, BUFSIZE, fmt, arg_values);
    // Return value is required size EXCLUDING null byte
    if (size >= BUFSIZE) {
      std::cerr << "syscall() command to long (" << size << " bytes): ";
      std::cerr << buffer << std::endl;
      return;
    }
    bpftrace->out_->message(MessageType::syscall, exec_system(buffer), false);
    return;
  }
  else if ( printf_id >= asyncactionint(AsyncAction::cat))
  {
    auto id = printf_id - asyncactionint(AsyncAction::cat);
    auto fmt = std::get<0>(bpftrace->cat_args_[id]).c_str();
    auto args = std::get<1>(bpftrace->cat_args_[id]);
    auto arg_values = bpftrace->get_arg_values(args, arg_data);

    const int BUFSIZE = 512;
    char buffer[BUFSIZE];
    int size = format(buffer, BUFSIZE, fmt, arg_values);
    // Return value is required size EXCLUDING null byte
    if (size >= BUFSIZE) {
      std::cerr << "cat() command to long (" << size << " bytes): ";
      std::cerr << buffer << std::endl;
      return;
    }
    std::stringstream buf;
    cat_file(buffer, bpftrace->cat_bytes_max_, buf);
    bpftrace->out_->message(MessageType::cat, buf.str(), false);

    return;
  }

  // printf
  auto fmt = std::get<0>(bpftrace->printf_args_[printf_id]).c_str();
  auto args = std::get<1>(bpftrace->printf_args_[printf_id]);
  auto arg_values = bpftrace->get_arg_values(args, arg_data);

  // First try with a stack buffer, if that fails use a heap buffer
  const int BUFSIZE=512;
  char buffer[BUFSIZE];
  int required_size = format(buffer, BUFSIZE, fmt, arg_values);
  // Return value is required size EXCLUDING null byte
  if (required_size < BUFSIZE) {
    bpftrace->out_->message(MessageType::printf, std::string(buffer), false);
  } else {
    auto buf = std::make_unique<char[]>(required_size+1);
    // if for some reason the size is still wrong the string
    // will just be silently truncated
    format(buf.get(), required_size, fmt, arg_values);
    bpftrace->out_->message(MessageType::printf, std::string(buf.get()), false);
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
              *reinterpret_cast<int64_t*>(arg_data+arg.offset),
              reinterpret_cast<uint8_t*>(arg_data+arg.offset + 8))));
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

void BPFtrace::add_param(const std::string &param)
{
  params_.emplace_back(param);
}

std::string BPFtrace::get_param(size_t i, bool is_str) const
{
  if (params_.size() < i) {
    return is_str ? "" : "0";
  }
  return params_.at(i-1);
}

size_t BPFtrace::num_params() const
{
  return params_.size();
}

void perf_event_lost(void *cb_cookie, uint64_t lost)
{
  auto bpftrace = static_cast<BPFtrace*>(cb_cookie);
  bpftrace->out_->lost_events(lost);
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
    if (probe.type == ProbeType::usdt || probe.type == ProbeType::watchpoint)
      return std::make_unique<AttachedProbe>(probe, func->second, pid_);
    else
      return std::make_unique<AttachedProbe>(probe, func->second, safe_mode_);
  }
  catch (std::runtime_error &e)
  {
    std::cerr << e.what() << std::endl;
  }
  return nullptr;
}

bool attach_reverse(const Probe &p)
{
  switch(p.type)
  {
    case ProbeType::kprobe:
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::usdt:
    case ProbeType::software:
      return true;
    case ProbeType::kretprobe:
    case ProbeType::tracepoint:
    case ProbeType::profile:
    case ProbeType::interval:
    case ProbeType::watchpoint:
    case ProbeType::hardware:
      return false;
    default:
      abort();
  }
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

  if (elapsed_map_)
  {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    auto nsec = 1000000000ULL * ts.tv_sec + ts.tv_nsec;
    uint64_t key = 0;

    if (bpf_update_elem(elapsed_map_->mapfd_, &key, &nsec, 0) < 0)
    {
      perror("Failed to write start time to elapsed map");
      return -1;
    }
  }

  BEGIN_trigger();

  // The kernel appears to fire some probes in the order that they were
  // attached and others in reverse order. In order to make sure that blocks
  // are executed in the same order they were declared, iterate over the probes
  // twice: in the first pass iterate forward and attach the probes that will
  // be fired in the same order they were attached, and in the second pass
  // iterate in reverse and attach the rest.
  for (auto probes = probes_.begin(); probes != probes_.end(); ++probes)
  {
    if (!attach_reverse(*probes)) {
      auto attached_probe = attach_probe(*probes, *bpforc.get());
      if (attached_probe == nullptr)
      {
        kill_child();
        return -1;
      }
      attached_probes_.push_back(std::move(attached_probe));
    }
  }

  for (auto r_probes = probes_.rbegin(); r_probes != probes_.rend(); ++r_probes)
  {
    if (attach_reverse(*r_probes)) {
      auto attached_probe = attach_probe(*r_probes, *bpforc.get());
      if (attached_probe == nullptr)
      {
        kill_child();
        return -1;
      }
      attached_probes_.push_back(std::move(attached_probe));
    }
  }

  // Kick the child to execute the command.
  if (has_child_cmd())
  {
    int ret = write(child_start_pipe_, &CHILD_GO, 1);
    if (ret < 0)
    {
      perror("unable to write to 'go' pipe");
      return ret;
    }

    child_running_ = true;
    close(child_start_pipe_);
  }

  if (bt_verbose)
    std::cerr << "Running..." << std::endl;

  poll_perf_events(epollfd);
  attached_probes_.clear();
  // finalize_ and exitsig_recv should be false from now on otherwise
  // perf_event_printer() can ignore the END_trigger() events.
  finalize_ = false;
  exitsig_recv = false;

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
    if (ready < 0 && errno == EINTR && !BPFtrace::exitsig_recv) {
      // We received an interrupt not caused by SIGINT, skip and run again
      continue;
    }

    // Return if either
    //   * epoll_wait has encountered an error (eg signal delivery)
    //   * There's no events left and we've been instructed to drain or
    //     finalization has been requested through exit() builtin.
    if (ready < 0 || (ready == 0 && (drain || finalize_)))
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
  uint32_t nvalues = map.is_per_cpu_type() ? ncpus_ : 1;
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

  int value_size = map.type_.size * nvalues;
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

std::string BPFtrace::map_value_to_str(IMap &map, std::vector<uint8_t> value, uint32_t div)
{
  uint32_t nvalues = map.is_per_cpu_type() ? ncpus_ : 1;
  if (map.type_.type == Type::kstack)
    return get_stack(*(uint64_t*)value.data(), false, map.type_.stack_type, 8);
  else if (map.type_.type == Type::ustack)
    return get_stack(*(uint64_t*)value.data(), true, map.type_.stack_type, 8);
  else if (map.type_.type == Type::ksym)
    return resolve_ksym(*(uintptr_t*)value.data());
  else if (map.type_.type == Type::usym)
    return resolve_usym(*(uintptr_t*)value.data(), *(uint64_t*)(value.data() + 8));
  else if (map.type_.type == Type::inet)
    return resolve_inet(*(int32_t*)value.data(), (uint8_t*)(value.data() + 8));
  else if (map.type_.type == Type::username)
    return resolve_uid(*(uint64_t*)(value.data()));
  else if (map.type_.type == Type::string)
    return std::string(reinterpret_cast<const char*>(value.data()));
  else if (map.type_.type == Type::count)
    return std::to_string(reduce_value<uint64_t>(value, nvalues) / div);
  else if (map.type_.type == Type::sum || map.type_.type == Type::integer) {
    if (map.type_.is_signed)
      return std::to_string(reduce_value<int64_t>(value, nvalues) / div);

    return std::to_string(reduce_value<uint64_t>(value, nvalues) / div);
  }
  else if (map.type_.type == Type::min)
    return std::to_string(min_value(value, nvalues) / div);
  else if (map.type_.type == Type::max)
    return std::to_string(max_value(value, nvalues) / div);
  else if (map.type_.type == Type::probe)
    return resolve_probe(*(uint64_t*)value.data());
  else
    return std::to_string(*(int64_t*)value.data() / div);
}

int BPFtrace::print_map(IMap &map, uint32_t top, uint32_t div)
{
  uint32_t nvalues = map.is_per_cpu_type() ? ncpus_ : 1;
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
    value_size *= nvalues;
    auto value = std::vector<uint8_t>(value_size);
    int err = bpf_lookup_elem(map.mapfd_, key.data(), value.data());
    if (err == -1)
    {
      // key was removed by the eBPF program during bpf_get_next_key() and bpf_lookup_elem(),
      // let's skip this key
      continue;
    }
    else if (err)
    {
      std::cerr << "Error looking up elem: " << err << std::endl;
      return -1;
    }

    values_by_key.push_back({key, value});

    old_key = key;
  }

  if (map.type_.type == Type::count || map.type_.type == Type::sum || map.type_.type == Type::integer)
  {
    bool is_signed = map.type_.is_signed;
    std::sort(values_by_key.begin(), values_by_key.end(), [&](auto &a, auto &b)
    {
      if (is_signed)
        return reduce_value<int64_t>(a.second, nvalues) < reduce_value<int64_t>(b.second, nvalues);
      return reduce_value<uint64_t>(a.second, nvalues) < reduce_value<uint64_t>(b.second, nvalues);
    });
  }
  else if (map.type_.type == Type::min)
  {
    std::sort(values_by_key.begin(), values_by_key.end(), [&](auto &a, auto &b)
    {
      return min_value(a.second, nvalues) < min_value(b.second, nvalues);
    });
  }
  else if (map.type_.type == Type::max)
  {
    std::sort(values_by_key.begin(), values_by_key.end(), [&](auto &a, auto &b)
    {
      return max_value(a.second, nvalues) < max_value(b.second, nvalues);
    });
  }
  else
  {
    sort_by_key(map.key_.args_, values_by_key);
  };

  if (div == 0)
    div = 1;
  out_->map(*this, map, top, div, values_by_key);
  return 0;
}

int BPFtrace::print_map_hist(IMap &map, uint32_t top, uint32_t div)
{
  // A hist-map adds an extra 8 bytes onto the end of its key for storing
  // the bucket number.
  // e.g. A map defined as: @x[1, 2] = @hist(3);
  // would actually be stored with the key: [1, 2, 3]

  uint32_t nvalues = map.is_per_cpu_type() ? ncpus_ : 1;
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

    int value_size = map.type_.size * nvalues;
    auto value = std::vector<uint8_t>(value_size);
    int err = bpf_lookup_elem(map.mapfd_, key.data(), value.data());
    if (err == -1)
    {
      // key was removed by the eBPF program during bpf_get_next_key() and bpf_lookup_elem(),
      // let's skip this key
      continue;
    }
    else if (err)
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
    values_by_key[key_prefix].at(bucket) = reduce_value<uint64_t>(value, nvalues);

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
  out_->map_hist(*this, map, top, div, values_by_key, total_counts_by_key);
  return 0;
}

int BPFtrace::print_map_stats(IMap &map)
{
  uint32_t nvalues = map.is_per_cpu_type() ? ncpus_ : 1;
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

  std::map<std::vector<uint8_t>, std::vector<int64_t>> values_by_key;

  while (bpf_get_next_key(map.mapfd_, old_key.data(), key.data()) == 0)
  {
    auto key_prefix = std::vector<uint8_t>(map.key_.size());
    int bucket = key.at(map.key_.size());

    for (size_t i=0; i<map.key_.size(); i++)
      key_prefix.at(i) = key.at(i);

    int value_size = map.type_.size * nvalues;
    auto value = std::vector<uint8_t>(value_size);
    int err = bpf_lookup_elem(map.mapfd_, key.data(), value.data());
    if (err == -1)
    {
      // key was removed by the eBPF program during bpf_get_next_key() and bpf_lookup_elem(),
      // let's skip this key
      continue;
    }
    else if (err)
    {
      std::cerr << "Error looking up elem: " << err << std::endl;
      return -1;
    }

    if (values_by_key.find(key_prefix) == values_by_key.end())
    {
      // New key - create a list of buckets for it
      values_by_key[key_prefix] = std::vector<int64_t>(2);
    }
    values_by_key[key_prefix].at(bucket) = reduce_value<int64_t>(value, nvalues);

    old_key = key;
  }

  // Sort based on sum of counts in all buckets
  std::vector<std::pair<std::vector<uint8_t>, int64_t>> total_counts_by_key;
  for (auto &map_elem : values_by_key)
  {
    assert(map_elem.second.size() == 2);
    int64_t count = map_elem.second.at(0);
    int64_t total = map_elem.second.at(1);
    int64_t value = 0;

    if (count != 0)
      value = total / count;

    total_counts_by_key.push_back({map_elem.first, value});
  }
  std::sort(total_counts_by_key.begin(), total_counts_by_key.end(), [&](auto &a, auto &b)
  {
    return a.second < b.second;
  });

  out_->map_stats(*this, map, values_by_key, total_counts_by_key);
  return 0;
}

pid_t BPFtrace::spawn_child()
{
  static const int maxargs = 256;
  char* argv[maxargs];
  int wait_for_tracing_pipe[2];

  auto args = split_string(cmd_, ' ');
  auto paths = resolve_binary_path(args[0]); // does path lookup on executable
  switch (paths.size())
  {
  case 0:
    std::cerr << "path '" << args[0] << "' does not exist or is not executable" << std::endl;
    return -1;
  case 1:
    args[0] = paths.front().c_str();
    break;
  default:
    std::cerr << "path '" << args[0] << "' must refer to a unique binary but matched "
              << paths.size() << " binaries" << std::endl;
    return -1;
  }


  if (args.size() >= (maxargs - 1))
  {
    std::cerr << "Too many args passed into spawn_child (" << args.size()
              << " > " << maxargs - 1 << ")" << std::endl;
    return -1;
  }

  // Convert vector of strings into raw array of C-strings for execve(2)
  int idx = 0;
  for (const auto& arg : args)
  {
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
  pid_t pid = fork();
  if (pid == 0)
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

    int ret = read(wait_for_tracing_pipe[0], &bf, 1);
    if (ret != 1)
    {
      perror("failed to read 'go' pipe");
      return -1;
    }

    if (bf == CHILD_EXIT_QUIETLY)
    {
      close(wait_for_tracing_pipe[0]);
      exit(0);
    }

    if (execve(argv[0], argv, environ))
    {
      auto err = "Failed to execve: " + std::string(argv[0]);
      perror(err.c_str());
      return -1;
    }
  }
  else if (pid > 0)
  {
    close(wait_for_tracing_pipe[0]);
    child_start_pipe_ = wait_for_tracing_pipe[1];
    child_pid_ = pid;
    pid_ = pid;
    return pid;
  }
  else
  {
    perror("Failed to fork");
    return -1;
  }

  return -1;  // silence end of control compiler warning
}

template <typename T>
T BPFtrace::reduce_value(const std::vector<uint8_t> &value, int nvalues)
{
  T sum = 0;
  for (int i=0; i<nvalues; i++)
  {
    sum += *(const T*)(value.data() + i*sizeof(T*));
  }
  return sum;
}

uint64_t BPFtrace::max_value(const std::vector<uint8_t> &value, int nvalues)
{
  uint64_t val, max = 0;
  for (int i=0; i<nvalues; i++)
  {
    val = *(const uint64_t*)(value.data() + i*sizeof(uint64_t*));
    if (val > max)
      max = val;
  }
  return max;
}

int64_t BPFtrace::min_value(const std::vector<uint8_t> &value, int nvalues)
{
  int64_t val, max = 0, retval;
  for (int i=0; i<nvalues; i++)
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
  uint32_t nvalues = map.is_per_cpu_type() ? ncpus_ : 1;
  int value_size = map.type_.size * nvalues;
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

std::string BPFtrace::resolve_uid(uintptr_t addr) const
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

uint64_t BPFtrace::resolve_kname(const std::string &name) const
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

  while (std::getline(file, line) && addr == 0)
  {
    auto tokens = split_string(line, ' ');

    if (name == tokens[2])
    {
      addr = read_address_from_output(line);
      break;
    }
  }

  file.close();

  return addr;
}

uint64_t BPFtrace::resolve_cgroupid(const std::string &path) const
{
  return bpftrace_linux::resolve_cgroupid(path);
}

#ifdef HAVE_BCC_ELF_FOREACH_SYM
static int sym_resolve_callback(const char *name,
                                uint64_t addr,
                                uint64_t size,
                                void *payload)
{
  struct symbol *sym = (struct symbol *)payload;
  if (!strcmp(name, sym->name.c_str()))
  {
    sym->address = addr;
    sym->size = size;
    return -1;
  }
  return 0;
}
#endif

int BPFtrace::resolve_uname(const std::string &name,
                            struct symbol *sym,
                            const std::string &path) const
{
  sym->name = name;
#ifdef HAVE_BCC_ELF_FOREACH_SYM
  struct bcc_symbol_option option;
  memset(&option, 0, sizeof(option));
  option.use_symbol_type = (1 << STT_OBJECT);

  return bcc_elf_foreach_sym(path.c_str(), sym_resolve_callback, &option, sym);
#else
  std::string call_str =
      std::string("objdump -tT ") + path + " | grep -w " + sym->name;
  const char *call = call_str.c_str();
  auto result = exec_system(call);
  sym->address = read_address_from_output(result);
  /* Trying to grab the size from objdump output is not that easy. foreaech_sym
     has been around for a while, users should switch to that.
  */
  sym->size = 8;
  return 0;
#endif
}

#ifdef HAVE_BCC_ELF_FOREACH_SYM
static int add_symbol(const char *symname, uint64_t /*start*/, uint64_t /*size*/, void *payload) {
  auto syms = static_cast<std::ostringstream*>(payload);
  *syms << std::string(symname) << std::endl;
  return 0;
}
#endif

std::string BPFtrace::extract_func_symbols_from_path(const std::string &path) const
{
#ifdef HAVE_BCC_ELF_FOREACH_SYM
  struct bcc_symbol_option symbol_option;
  memset(&symbol_option, 0, sizeof(symbol_option));
  symbol_option.use_debug_file = 1;
  symbol_option.check_debug_file_crc = 1;
  symbol_option.use_symbol_type = (1 << STT_FUNC) | (1 << STT_GNU_IFUNC);

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

static std::string resolve_inetv4(const uint8_t* inet) {
  char addr_cstr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, inet, addr_cstr, INET_ADDRSTRLEN);
  return std::string(addr_cstr);
}


static std::string resolve_inetv6(const uint8_t* inet) {
  char addr_cstr[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, inet, addr_cstr, INET6_ADDRSTRLEN);
  return std::string(addr_cstr);
}


std::string BPFtrace::resolve_inet(int af, const uint8_t* inet) const
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
  void *psyms = nullptr;
  struct bcc_symbol_option symopts;

  memset(&symopts, 0, sizeof(symopts));
  symopts.use_debug_file = 1;
  symopts.check_debug_file_crc = 1;
  symopts.use_symbol_type = BCC_SYM_ALL_TYPES;

  if (resolve_user_symbols_)
  {
    std::string pid_exe = get_pid_exe(pid);
    if (exe_sym_.find(pid_exe) == exe_sym_.end())
    {
      // not cached, create new ProcSyms cache
      psyms = bcc_symcache_new(pid, &symopts);
      exe_sym_[pid_exe] = std::make_pair(pid, psyms);
    }
    else
    {
      psyms = exe_sym_[pid_exe].second;
    }
  }

  if (psyms && bcc_symcache_resolve(psyms, addr, &usym) == 0)
  {
    if (demangle_cpp_symbols_)
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

std::string BPFtrace::resolve_probe(uint64_t probe_id) const
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

const std::string BPFtrace::get_source_line(unsigned int n)
{
  // Get the Nth source line. Return an empty string if it doesn't exist
  std::string buf;
  std::stringstream ss(src_);
  for (unsigned int idx = 0; idx <= n; idx++) {
    std::getline(ss, buf);
    if (ss.eof() && idx == n)
      return buf;
    if (!ss)
      return "";
  }
  return buf;
}

void BPFtrace::warning(std::ostream &out, const location &l, const std::string &m) {
  log_with_location("WARNING", out, l, m);
}

void BPFtrace::error(std::ostream &out, const location &l, const std::string &m) {
  log_with_location("ERROR", out, l, m);
}

void BPFtrace::log_with_location(std::string level, std::ostream &out, const location &l, const std::string &m)
{
  if (filename_ != "") {
    out << filename_ << ":";
  }

  std::string msg(m);

  if (! msg.empty() && msg[msg.length() -1 ] == '\n') {
    msg.erase(msg.length()-1);
  }

  // print only the message if location info wasn't set
  if (l.begin.line == 0) {
    out << level << ": " << msg << std::endl;
    return;
  }

  if (l.begin.line > l.end.line) {
    out << "BUG: begin > end: " << l.begin << ":" << l.end << std::endl;
    out << level << ": " << msg << std::endl;
    return;
  }

  /* For a multi line error only the line range is printed:
     <filename>:<start_line>-<end_line>: ERROR: <message>
  */
  if (l.begin.line < l.end.line) {
    out << l.begin.line << "-" << l.end.line << ": ERROR: " << msg << std::endl;
    return;
  }

  /*
    For a single line error the format is:

    <filename>:<line>:<start_col>-<end_col>: ERROR: <message>
    <source line>
    <marker>

    E.g.

    file.bt:1:10-20: error: <message>
    i:s:1   /1 < "str"/
            ~~~~~~~~~~
  */
  out << l.begin.line << ":" << l.begin.column << "-" << l.end.column;
  out << ": " << level << ": " << msg << std::endl;
  std::string srcline = get_source_line(l.begin.line - 1);

  if (srcline == "")
    return;

  // To get consistent printing all tabs will be replaced with 4 spaces
  for (auto c : srcline) {
    if (c == '\t')
      out << "    ";
    else
      out << c;
  }
  out << std::endl;

  for (unsigned int x = 0;
       x < srcline.size() && x < (static_cast<unsigned int>(l.end.column) - 1);
       x++)
  {
    char marker = (x < (static_cast<unsigned int>(l.begin.column) - 1)) ? ' '
                                                                        : '~';
    if (srcline[x] == '\t') {
      out << std::string(4, marker);
    } else {
      out << marker;
    }
  }
  out << std::endl;
}

} // namespace bpftrace
