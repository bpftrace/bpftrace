#include <arpa/inet.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <glob.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <sys/epoll.h>

#include <fcntl.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef HAVE_BCC_ELF_FOREACH_SYM
#include <linux/elf.h>

#include <bcc/bcc_elf.h>
#endif

#include <bcc/bcc_syms.h>
#include <bcc/perf_reader.h>

#include <llvm/Demangle/Demangle.h>

#include "ast/async_event_types.h"
#include "attached_probe.h"
#include "bpforc.h"
#include "bpftrace.h"
#include "log.h"
#include "printf.h"
#include "resolve_cgroupid.h"
#include "triggers.h"
#include "utils.h"

namespace libbpf {
#define __BPF_NAME_FN(x) #x
const char *bpf_func_name[] = { __BPF_FUNC_MAPPER(__BPF_NAME_FN) };
#undef __BPF_NAME_FN
} // namespace libbpf

namespace bpftrace {
namespace {
/*
 * Finds all matches of func in the provided input stream.
 *
 * If an optional prefix is provided, lines must start with it to count as a
 * match, but the prefix is stripped from entries in the result set.
 * Wildcard tokens ("*") are accepted in func.
 *
 * If `ignore_trailing_module` is true, will ignore trailing kernel module.
 * For example, `[ehci_hcd]` will be ignored in:
 *     ehci_disable_ASE [ehci_hcd]
 */
std::set<std::string> find_wildcard_matches_internal(
    const std::string &func,
    bool ignore_trailing_module,
    std::istream &symbol_stream)
{
  if (!bpftrace::has_wildcard(func))
    return std::set<std::string>({ func });
  bool start_wildcard = func[0] == '*';
  bool end_wildcard = func[func.length() - 1] == '*';

  std::vector<std::string> tokens = split_string(func, '*');
  tokens.erase(std::remove(tokens.begin(), tokens.end(), ""), tokens.end());

  std::string line;
  std::set<std::string> matches;
  while (std::getline(symbol_stream, line))
  {
    if (ignore_trailing_module && line.size() && line[line.size() - 1] == ']')
    {
      if (size_t idx = line.rfind(" ["); idx != std::string::npos)
        line = line.substr(0, idx);
    }

    if (!wildcard_match(line, tokens, start_wildcard, end_wildcard))
    {
      auto fun_line = line;
      auto prefix = fun_line.find(':') != std::string::npos
                        ? erase_prefix(fun_line) + ":"
                        : "";
      if (symbol_has_cpp_mangled_signature(fun_line))
      {
        char *demangled_name = llvm::itaniumDemangle(
            fun_line.c_str(), nullptr, nullptr, nullptr);
        if (demangled_name)
        {
          if (!wildcard_match(prefix + demangled_name, tokens, true, true))
          {
            free(demangled_name);
          }
          else
          {
            free(demangled_name);
            goto out;
          }
        }
      }
      continue;
    }
  out:
    // skip the ".part.N" kprobe variants, as they can't be traced:
    if (line.find(".part.") != std::string::npos)
      continue;

    matches.insert(line);
  }
  return matches;
}
} // namespace

DebugLevel bt_debug = DebugLevel::kNone;
bool bt_quiet = false;
bool bt_verbose = false;
volatile sig_atomic_t BPFtrace::exitsig_recv = false;
const int FMT_BUF_SZ = 512;

std::string format(std::string fmt,
                   std::vector<std::unique_ptr<IPrintable>> &args)
{
  std::string retstr;
  auto buffer = std::vector<char>(FMT_BUF_SZ);
  auto check_snprintf_ret = [](int r) {
    if (r < 0)
    {
      LOG(FATAL) << "format() error occurred: " << std::strerror(errno);
    }
  };
  // Args have been made safe for printing by now, so replace nonstandard format
  // specifiers with %s
  size_t start_pos = 0;
  while ((start_pos = fmt.find("%r", start_pos)) != std::string::npos)
  {
    fmt.replace(start_pos, 2, "%s");
    start_pos += 2;
  }

  auto tokens_begin = std::sregex_iterator(fmt.begin(),
                                           fmt.end(),
                                           format_specifier_re);
  auto tokens_end = std::sregex_iterator();

  // replace format string tokens with args one by one
  int literal_text_pos = 0; // starting pos of literal text (text that is not
                            // format specifier)
  int i = 0;                // args index
  while (tokens_begin != tokens_end)
  {
    // take out the literal text
    retstr += fmt.substr(literal_text_pos,
                         tokens_begin->position() - literal_text_pos);
    // replace current specifier with an arg
    int r = args.at(i)->print(buffer.data(),
                              buffer.capacity(),
                              tokens_begin->str().c_str());

    check_snprintf_ret(r);
    if (static_cast<size_t>(r) >= buffer.capacity())
    {
      // the buffer is not big enough to hold the string, resize it
      buffer.resize(r + 1);
      int r = args.at(i)->print(buffer.data(),
                                buffer.capacity(),
                                tokens_begin->str().c_str());
      check_snprintf_ret(r);
    }
    retstr += std::string(buffer.data());
    // move to the next literal text
    literal_text_pos = tokens_begin->position() + tokens_begin->length();
    ++tokens_begin;
    ++i;
  }
  // append whatever is left
  retstr += fmt.substr(literal_text_pos);
  return retstr;
}

BPFtrace::~BPFtrace()
{
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
    // An underspecified usdt probe is a probe that has no wildcards and
    // either an empty namespace or a specified PID.
    // We try to find a unique match for such a probe.
    bool underspecified_usdt_probe = probetype(attach_point->provider) ==
                                         ProbeType::usdt &&
                                     !has_wildcard(attach_point->target) &&
                                     !has_wildcard(attach_point->ns) &&
                                     !has_wildcard(attach_point->func) &&
                                     (attach_point->ns.empty() || pid() > 0);
    if (attach_point->need_expansion &&
        (has_wildcard(attach_point->func) ||
         has_wildcard(attach_point->target) || has_wildcard(attach_point->ns) ||
         underspecified_usdt_probe))
    {
      std::set<std::string> matches;
      try
      {
        matches = find_wildcard_matches(*attach_point);
      }
      catch (const WildcardException &e)
      {
        LOG(ERROR) << e.what();
        return 1;
      }

      if (underspecified_usdt_probe && matches.size() > 1)
      {
        LOG(ERROR) << "namespace for " << attach_point->name(attach_point->func)
                   << " not specified, matched " << matches.size() << " probes";
        LOG(INFO) << "please specify a unique namespace or use '*' to attach "
                  << "to all matched probes";
        return 1;
      }

      attach_funcs.insert(attach_funcs.end(), matches.begin(), matches.end());
    }
    else if ((probetype(attach_point->provider) == ProbeType::uprobe ||
              probetype(attach_point->provider) == ProbeType::uretprobe) &&
             !attach_point->func.empty())
    {
      std::set<std::string> matches;

      struct symbol sym = {};
      int err = resolve_uname(attach_point->func, &sym, attach_point->target);
      if (err < 0 || sym.address == 0)
      {
        // As the C++ language supports function overload, a given function name
        // (without parameters) could have multiple matches even when no
        // wildcards are used.
        matches = find_symbol_matches(*attach_point);
        attach_funcs.insert(attach_funcs.end(), matches.begin(), matches.end());
      }
      else
      {
        attach_funcs.push_back(attach_point->target + ":" + attach_point->func);
      }
    }
    else
    {
      if (probetype(attach_point->provider) == ProbeType::usdt &&
          !attach_point->ns.empty())
        attach_funcs.push_back(attach_point->target + ":" + attach_point->ns +
                               ":" + attach_point->func);
      else if (probetype(attach_point->provider) == ProbeType::tracepoint ||
               probetype(attach_point->provider) == ProbeType::uprobe ||
               probetype(attach_point->provider) == ProbeType::uretprobe)
        attach_funcs.push_back(attach_point->target + ":" + attach_point->func);
      else
        attach_funcs.push_back(attach_point->func);
    }

    for (const auto &func : attach_funcs)
    {
      std::string func_id = func;
      std::string target = attach_point->target;

      // USDT probes must specify a target binary path, a provider, and
      // a function name for full id.
      // So we will extract out the path and the provider namespace to get just
      // the function name
      if (probetype(attach_point->provider) == ProbeType::usdt )
      {
        target = erase_prefix(func_id);
        std::string ns = erase_prefix(func_id);
        // Set attach_point target, ns, and func to their resolved values in
        // case of wildcards.
        attach_point->target = target;
        attach_point->ns = ns;
        attach_point->func = func_id;
      }
      else if (probetype(attach_point->provider) == ProbeType::tracepoint ||
               probetype(attach_point->provider) == ProbeType::uprobe ||
               probetype(attach_point->provider) == ProbeType::uretprobe)
      {
        // tracepoint and uprobe probes must specify both a target and
        // a function name.
        // We extract the target from func_id so that a resolved target and a
        // resolved function name are used in the probe.
        target = erase_prefix(func_id);
      }

      Probe probe;
      probe.path = target;
      probe.attach_point = func_id;
      probe.type = probetype(attach_point->provider);
      probe.log_size = log_size_;
      probe.orig_name = p.name();
      probe.ns = attach_point->ns;
      probe.name = attach_point->name(target, func_id);
      probe.freq = attach_point->freq;
      probe.address = attach_point->address;
      probe.func_offset = attach_point->func_offset;
      probe.loc = 0;
      probe.index = attach_point->index(func) > 0 ? attach_point->index(func)
                                                  : p.index();
      probe.len = attach_point->len;
      probe.mode = attach_point->mode;

      if (probetype(attach_point->provider) == ProbeType::usdt)
      {
        // We must attach to all locations of a USDT marker if duplicates exist
        // in a target binary. See comment in codegen_llvm.cpp probe generation
        // code for more details.
        for (int i = 0; i < attach_point->usdt.num_locations; ++i)
        {
          Probe probe_copy = probe;
          probe_copy.usdt_location_idx = i;
          probe_copy.index = attach_point->index(func + "_loc" +
                                                 std::to_string(i));

          probes_.emplace_back(std::move(probe_copy));
        }
      }
      else
      {
        probes_.push_back(probe);
      }
    }
  }

  return 0;
}

std::set<std::string> BPFtrace::find_wildcard_matches(
    const ast::AttachPoint &attach_point) const
{
  std::unique_ptr<std::istream> symbol_stream;
  bool ignore_trailing_module = false;
  std::string func;

  switch (probetype(attach_point.provider))
  {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
    {
      symbol_stream = get_symbols_from_file(
          "/sys/kernel/debug/tracing/available_filter_functions");
      func = attach_point.func;
      ignore_trailing_module = true;
      break;
    }
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    {
      symbol_stream = std::make_unique<std::istringstream>(
          extract_func_symbols_from_path(attach_point.target));
      func = attach_point.target + ":" + attach_point.func;
      break;
    }
    case ProbeType::tracepoint:
    {
      symbol_stream = get_symbols_from_file(
          "/sys/kernel/debug/tracing/available_events");
      func = attach_point.target + ":" + attach_point.func;
      break;
    }
    case ProbeType::usdt:
    {
      symbol_stream = get_symbols_from_usdt(pid(), attach_point.target);
      auto target = attach_point.target;
      // If PID is specified, targets in symbol_stream will have the
      // "/proc/<PID>/root" prefix followed by an absolute path, so we make the
      // target absolute and add a leading wildcard.
      if (pid() > 0)
      {
        if (target != "")
          target = abs_path(target);
        target = "*" + target;
      }
      auto ns = attach_point.ns == "" ? "*" : attach_point.ns;
      func = target + ":" + ns + ":" + attach_point.func;
      break;
    }
    case ProbeType::kfunc:
    case ProbeType::kretfunc: {
      symbol_stream = btf_.kfunc();
      func = attach_point.func;
      break;
    }
    default:
    {
      throw WildcardException("Wildcard matches aren't available on probe type '"
          + attach_point.provider + "'");
    }
  }

  return find_wildcard_matches_internal(func,
                                        ignore_trailing_module,
                                        *symbol_stream);
}

std::set<std::string> BPFtrace::find_symbol_matches(
    const ast::AttachPoint &attach_point) const
{
  std::unique_ptr<std::istream> symbol_stream;
  std::string prefix, func;

  symbol_stream = std::make_unique<std::istringstream>(
      extract_func_symbols_from_path(attach_point.target));
  func = attach_point.func;

  std::string line;
  std::set<std::string> matches;
  while (std::getline(*symbol_stream, line))
  {
    auto line_func = line;
    erase_prefix(line_func); // remove the "path:" prefix from line
    if (line_func != func)
    {
      if (symbol_has_cpp_mangled_signature(line_func))
      {
        char *demangled_name = llvm::itaniumDemangle(
            line_func.c_str(), nullptr, nullptr, nullptr);
        if (demangled_name)
        {
          std::string symbol_name;
          // If the specified function name has a '(', try to match it against
          // the full demangled symbol (including parameters), otherwise just
          // against the function name (without parameters)
          if (func.find('(') != std::string::npos)
            symbol_name = demangled_name;
          else
            symbol_name =
                std::string(demangled_name)
                    .substr(0, std::string(demangled_name).find_first_of("("));
          free(demangled_name);
          if (symbol_name == func)
            matches.insert(line);
        }
      }
    }
    else
    {
      matches.insert(line);
    }
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
  {
    std::vector<std::string> real_paths;
    if (target.find('*') != std::string::npos)
      real_paths = resolve_binary_path(target);
    else
      real_paths.push_back(target);

    for (auto &real_path : real_paths)
    {
      auto target_usdt_probes = USDTHelper::probes_for_path(real_path);
      usdt_probes.insert(usdt_probes.end(),
                         target_usdt_probes.begin(),
                         target_usdt_probes.end());
    }
  }

  for (auto const& usdt_probe : usdt_probes)
  {
    std::string path = usdt_probe.path;
    std::string provider = usdt_probe.provider;
    std::string fname = usdt_probe.name;
    probes += path + ":" + provider + ":" + fname + "\n";
  }

  return std::make_unique<std::istringstream>(probes);
}

int BPFtrace::num_probes() const
{
  return special_probes_.size() + probes_.size();
}

void BPFtrace::request_finalize()
{
  finalize_ = true;
  attached_probes_.clear();
  if (child_)
    child_->terminate();
}

void perf_event_printer(void *cb_cookie, void *data, int size)
{
  // The perf event data is not aligned, so we use memcpy to copy the data and
  // avoid UBSAN errors. Using an std::vector guarantees that it will be aligned
  // to the largest type. See:
  // https://stackoverflow.com/questions/8456236/how-is-a-vectors-data-aligned.
  std::vector<uint8_t> data_aligned;
  data_aligned.resize(size);
  memcpy(data_aligned.data(), data, size);

  auto bpftrace = static_cast<BPFtrace*>(cb_cookie);
  auto arg_data = data_aligned.data();

  auto printf_id = *reinterpret_cast<uint64_t *>(arg_data);

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
    auto print = static_cast<AsyncEvent::Print *>(data);
    IMap *map = *bpftrace->maps[print->mapid];

    err = bpftrace->print_map(*map, print->top, print->div);

    if (err)
      throw std::runtime_error("Could not print map with ident \"" +
                               map->name_ + "\", err=" + std::to_string(err));
    return;
  }
  else if (printf_id == asyncactionint(AsyncAction::print_non_map))
  {
    auto print = static_cast<AsyncEvent::PrintNonMap *>(data);
    const SizedType &ty = bpftrace->non_map_print_args_.at(print->print_id);

    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < ty.GetSize(); ++i)
      bytes.emplace_back(reinterpret_cast<uint8_t>(print->content[i]));

    bpftrace->out_->value(*bpftrace, ty, bytes);

    return;
  }
  else if (printf_id == asyncactionint(AsyncAction::clear))
  {
    auto mapevent = static_cast<AsyncEvent::MapEvent *>(data);
    IMap *map = *bpftrace->maps[mapevent->mapid];
    err = bpftrace->clear_map(*map);
    if (err)
      throw std::runtime_error("Could not clear map with ident \"" +
                               map->name_ + "\", err=" + std::to_string(err));
    return;
  }
  else if (printf_id == asyncactionint(AsyncAction::zero))
  {
    auto mapevent = static_cast<AsyncEvent::MapEvent *>(data);
    IMap *map = *bpftrace->maps[mapevent->mapid];
    err = bpftrace->zero_map(*map);
    if (err)
      throw std::runtime_error("Could not zero map with ident \"" + map->name_ +
                               "\", err=" + std::to_string(err));
    return;
  }
  else if (printf_id == asyncactionint(AsyncAction::time))
  {
    char timestr[STRING_SIZE];
    time_t t;
    struct tm tmp;
    t = time(NULL);
    if (!localtime_r(&t, &tmp))
    {
      LOG(ERROR) << "localtime_r: " << strerror(errno);
      return;
    }
    auto time = static_cast<AsyncEvent::Time *>(data);
    auto fmt = bpftrace->time_args_[time->time_id].c_str();
    if (strftime(timestr, sizeof(timestr), fmt, &tmp) == 0)
    {
      LOG(ERROR) << "strftime returned 0";
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
  else if (printf_id == asyncactionint(AsyncAction::helper_error))
  {
    auto helpererror = static_cast<AsyncEvent::HelperError *>(data);
    auto error_id = helpererror->error_id;
    auto return_value = helpererror->return_value;
    auto &info = bpftrace->helper_error_info_[error_id];
    std::stringstream msg;
    msg << "Failed to " << libbpf::bpf_func_name[info.func_id] << ": ";
    if (return_value < 0)
      msg << strerror(-return_value) << " (" << return_value << ")";
    else
      msg << return_value;
    LOG(WARNING, info.loc, std::cerr) << msg.str();
    return;
  }
  else if ( printf_id >= asyncactionint(AsyncAction::syscall) &&
            printf_id < asyncactionint(AsyncAction::syscall) + RESERVED_IDS_PER_ASYNCACTION)
  {
    if (bpftrace->safe_mode_)
    {
      LOG(FATAL) << "syscall() not allowed in safe mode";
    }

    auto id = printf_id - asyncactionint(AsyncAction::syscall);
    auto fmt = std::get<0>(bpftrace->system_args_[id]);
    auto args = std::get<1>(bpftrace->system_args_[id]);
    auto arg_values = bpftrace->get_arg_values(args, arg_data);

    bpftrace->out_->message(MessageType::syscall,
                            exec_system(format(fmt, arg_values).c_str()),
                            false);
    return;
  }
  else if ( printf_id >= asyncactionint(AsyncAction::cat))
  {
    auto id = printf_id - asyncactionint(AsyncAction::cat);
    auto fmt = std::get<0>(bpftrace->cat_args_[id]);
    auto args = std::get<1>(bpftrace->cat_args_[id]);
    auto arg_values = bpftrace->get_arg_values(args, arg_data);

    std::stringstream buf;
    cat_file(format(fmt, arg_values).c_str(), bpftrace->cat_bytes_max_, buf);
    bpftrace->out_->message(MessageType::cat, buf.str(), false);

    return;
  }

  // printf
  auto fmt = std::get<0>(bpftrace->printf_args_[printf_id]);
  auto args = std::get<1>(bpftrace->printf_args_[printf_id]);
  auto arg_values = bpftrace->get_arg_values(args, arg_data);

  bpftrace->out_->message(MessageType::printf, format(fmt, arg_values), false);
}

std::vector<std::unique_ptr<IPrintable>> BPFtrace::get_arg_values(const std::vector<Field> &args, uint8_t* arg_data)
{
  std::vector<std::unique_ptr<IPrintable>> arg_values;

  for (auto arg : args)
  {
    switch (arg.type.type)
    {
      case Type::integer:
        if (arg.type.IsSigned())
        {
          int64_t val = 0;
          switch (arg.type.GetIntBitWidth())
          {
            case 64:
              val = *reinterpret_cast<int64_t *>(arg_data + arg.offset);
              break;
            case 32:
              val = *reinterpret_cast<int32_t *>(arg_data + arg.offset);
              break;
            case 16:
              val = *reinterpret_cast<int16_t *>(arg_data + arg.offset);
              break;
            case 8:
              val = *reinterpret_cast<int8_t *>(arg_data + arg.offset);
              break;
            case 1:
              val = *reinterpret_cast<int8_t *>(arg_data + arg.offset);
              break;
            default:
              LOG(FATAL) << "get_arg_values: invalid integer size. 8, 4, 2 and "
                            "byte supported. "
                         << arg.type.GetSize() << "provided";
          }
          arg_values.push_back(std::make_unique<PrintableSInt>(val));
        }
        else
        {
          uint64_t val = 0;
          switch (arg.type.GetIntBitWidth())
          {
            case 64:
              val = *reinterpret_cast<uint64_t *>(arg_data + arg.offset);
              break;
            case 32:
              val = *reinterpret_cast<uint32_t *>(arg_data + arg.offset);
              break;
            case 16:
              val = *reinterpret_cast<uint16_t *>(arg_data + arg.offset);
              break;
            case 8:
              val = *reinterpret_cast<uint8_t *>(arg_data + arg.offset);
              break;
            case 1:
              val = *reinterpret_cast<uint8_t *>(arg_data + arg.offset);
              break;
            default:
              LOG(FATAL) << "get_arg_values: invalid integer size. 8, 4, 2 and "
                            "byte supported. "
                         << arg.type.GetSize() << "provided";
          }
          arg_values.push_back(std::make_unique<PrintableInt>(val));
        }
        break;
      case Type::string:
      {
        auto p = reinterpret_cast<char *>(arg_data + arg.offset);
        arg_values.push_back(std::make_unique<PrintableString>(
            std::string(p, strnlen(p, arg.type.GetSize()))));
        break;
      }
      case Type::buffer:
        arg_values.push_back(std::make_unique<PrintableString>(resolve_buf(
            reinterpret_cast<AsyncEvent::Buf *>(arg_data + arg.offset)->content,
            reinterpret_cast<AsyncEvent::Buf *>(arg_data + arg.offset)
                ->length)));
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
      case Type::timestamp:
        arg_values.push_back(
            std::make_unique<PrintableString>(resolve_timestamp(
                reinterpret_cast<AsyncEvent::Strftime *>(arg_data + arg.offset)
                    ->strftime_id,
                reinterpret_cast<AsyncEvent::Strftime *>(arg_data + arg.offset)
                    ->nsecs_since_boot)));
        break;
      case Type::pointer:
        arg_values.push_back(std::make_unique<PrintableInt>(
            *reinterpret_cast<uint64_t *>(arg_data + arg.offset)));
        break;
        // fall through
      default:
        LOG(FATAL) << "invalid argument type";
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

std::vector<std::unique_ptr<AttachedProbe>> BPFtrace::attach_usdt_probe(
    Probe &probe,
    std::tuple<uint8_t *, uintptr_t> func,
    int pid,
    bool file_activation)
{
  std::vector<std::unique_ptr<AttachedProbe>> ret;

  if (feature_->has_uprobe_refcnt() || !(file_activation && probe.path.size()))
  {
    ret.emplace_back(
        std::make_unique<AttachedProbe>(probe, func, pid, *feature_));
    return ret;
  }

  // File activation works by scanning through /proc/*/maps and seeing
  // which processes have the target executable in their address space
  // with execute permission. If found, we will try to attach to each
  // process we find.
  //
  // Note that this is the slow path. If the kernel has semaphore support
  // (feature_->has_uprobe_refcnt()), the kernel can do this for us and
  // much faster too.
  glob_t globbuf;
  if (::glob("/proc/[0-9]*/maps", GLOB_NOSORT, nullptr, &globbuf))
    throw std::runtime_error("failed to glob");

  char *p;
  if (!(p = realpath(probe.path.c_str(), nullptr)))
  {
    LOG(ERROR) << "Failed to resolve " << probe.path;
    return ret;
  }
  std::string resolved(p);
  free(p);

  for (size_t i = 0; i < globbuf.gl_pathc; ++i)
  {
    std::string path(globbuf.gl_pathv[i]);
    std::ifstream file(path);
    if (file.fail())
    {
      // The process could have exited between the glob and now. We have
      // to silently ignore that.
      continue;
    }

    std::string line;
    while (std::getline(file, line))
    {
      if (line.find(resolved) == std::string::npos)
        continue;

      auto parts = split_string(line, ' ');
      if (parts.at(1).find('x') == std::string::npos)
        continue;

      // Remove `/proc/` prefix
      std::string pid_str(globbuf.gl_pathv[i] + 6);
      // No need to remove `/maps` suffix b/c stoi() will ignore trailing !ints

      int pid_parsed;
      try
      {
        pid_parsed = std::stoi(pid_str);
      }
      catch (const std::exception &ex)
      {
        throw std::runtime_error("failed to parse pid=" + pid_str);
      }

      ret.emplace_back(
          std::make_unique<AttachedProbe>(probe, func, pid_parsed, *feature_));
      break;
    }
  }

  if (ret.empty())
    LOG(ERROR) << "Failed to find processes running " << probe.path;

  return ret;
}

std::vector<std::unique_ptr<AttachedProbe>> BPFtrace::attach_probe(
    Probe &probe,
    const BpfOrc &bpforc)
{
  std::vector<std::unique_ptr<AttachedProbe>> ret;

  std::string index_str = "_" + std::to_string(probe.index);
  if (probe.type == ProbeType::usdt)
    index_str = "_loc" + std::to_string(probe.usdt_location_idx) + index_str;

  // use the single-probe program if it exists (as is the case with wildcards
  // and the name builtin, which must be expanded into separate programs per
  // probe), else try to find a the program based on the original probe name
  // that includes wildcards.
  auto func = bpforc.sections_.find("s_" + probe.name + index_str);
  if (func == bpforc.sections_.end())
    func = bpforc.sections_.find("s_" + probe.orig_name + index_str);
  if (func == bpforc.sections_.end())
  {
    if (probe.name != probe.orig_name)
      LOG(ERROR) << "Code not generated for probe: " << probe.name
                 << " from: " << probe.orig_name;
    else
      LOG(ERROR) << "Code not generated for probe: " << probe.name;
    return ret;
  }
  try
  {
    pid_t pid = child_ ? child_->pid() : this->pid();

    if (probe.type == ProbeType::usdt)
    {
      auto aps = attach_usdt_probe(
          probe, func->second, pid, usdt_file_activation_);
      for (auto &ap : aps)
        ret.emplace_back(std::move(ap));

      return ret;
    }
    else if (probe.type == ProbeType::watchpoint)
    {
      ret.emplace_back(
          std::make_unique<AttachedProbe>(probe, func->second, pid, *feature_));
      return ret;
    }
    else
    {
      ret.emplace_back(
          std::make_unique<AttachedProbe>(probe, func->second, safe_mode_));
      return ret;
    }
  }
  catch (std::runtime_error &e)
  {
    LOG(ERROR) << e.what();
    ret.clear();
  }
  return ret;
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
    case ProbeType::kfunc:
      return true;
    case ProbeType::kretfunc:
    case ProbeType::kretprobe:
    case ProbeType::tracepoint:
    case ProbeType::profile:
    case ProbeType::interval:
    case ProbeType::watchpoint:
    case ProbeType::hardware:
      return false;
    case ProbeType::invalid:
      LOG(FATAL) << "Unknown probe type";
  }

  return {}; // unreached
}

int BPFtrace::run_special_probe(std::string name,
                                const BpfOrc &bpforc,
                                void (*trigger)(void))
{
  for (auto probe = special_probes_.rbegin(); probe != special_probes_.rend();
       ++probe)
  {
    if ((*probe).attach_point == name)
    {
      auto aps = attach_probe(*probe, bpforc);

      trigger();
      return aps.size() ? 0 : -1;
    }
  }

  return 0;
}

int BPFtrace::run(std::unique_ptr<BpfOrc> bpforc)
{
  int epollfd = setup_perf_events();
  if (epollfd < 0)
    return epollfd;

  if (maps.Has(MapManager::Type::Elapsed))
  {
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    auto nsec = 1000000000ULL * ts.tv_sec + ts.tv_nsec;
    uint64_t key = 0;

    if (bpf_update_elem(maps[MapManager::Type::Elapsed].value()->mapfd_,
                        &key,
                        &nsec,
                        0) < 0)
    {
      perror("Failed to write start time to elapsed map");
      return -1;
    }
  }

  if (run_special_probe("BEGIN_trigger", *bpforc.get(), BEGIN_trigger))
    return -1;

  if (child_ && has_usdt_)
  {
    try
    {
      child_->run(true);
    }
    catch (std::runtime_error &e)
    {
      LOG(ERROR) << "Failed to setup child: " << e.what();
      return -1;
    }
  }

  // The kernel appears to fire some probes in the order that they were
  // attached and others in reverse order. In order to make sure that blocks
  // are executed in the same order they were declared, iterate over the probes
  // twice: in the first pass iterate forward and attach the probes that will
  // be fired in the same order they were attached, and in the second pass
  // iterate in reverse and attach the rest.
  for (auto probes = probes_.begin(); probes != probes_.end(); ++probes)
  {
    if (!attach_reverse(*probes)) {
      auto aps = attach_probe(*probes, *bpforc.get());

      if (aps.empty())
        return -1;

      for (auto &ap : aps)
        attached_probes_.emplace_back(std::move(ap));
    }
  }

  for (auto r_probes = probes_.rbegin(); r_probes != probes_.rend(); ++r_probes)
  {
    if (attach_reverse(*r_probes)) {
      auto aps = attach_probe(*r_probes, *bpforc.get());

      if (aps.empty())
        return -1;

      for (auto &ap : aps)
        attached_probes_.emplace_back(std::move(ap));
    }
  }

  // Kick the child to execute the command.
  if (child_)
  {
    try
    {
      if (has_usdt_)
        child_->resume();
      else
        child_->run();
    }
    catch (std::runtime_error &e)
    {
      LOG(ERROR) << "Failed to run child: " << e.what();
      return -1;
    }
  }

  if (bt_verbose)
    std::cerr << "Running..." << std::endl;

  poll_perf_events(epollfd);
  attached_probes_.clear();
  // finalize_ and exitsig_recv should be false from now on otherwise
  // perf_event_printer() can ignore the END_trigger() events.
  finalize_ = false;
  exitsig_recv = false;

  if (run_special_probe("END_trigger", *bpforc.get(), END_trigger))
    return -1;

  poll_perf_events(epollfd, true);

  // Calls perf_reader_free() on all open perf buffers.
  open_perf_buffers_.clear();

  return 0;
}

int BPFtrace::setup_perf_events()
{
  int epollfd = epoll_create1(EPOLL_CLOEXEC);
  if (epollfd == -1)
  {
    LOG(ERROR) << "Failed to create epollfd";
    return -1;
  }

  std::vector<int> cpus = get_online_cpus();
  online_cpus_ = cpus.size();
  for (int cpu : cpus)
  {
    void *reader = bpf_open_perf_buffer(
        &perf_event_printer, &perf_event_lost, this, -1, cpu, perf_rb_pages_);
    if (reader == nullptr)
    {
      LOG(ERROR) << "Failed to open perf buffer";
      return -1;
    }
    // Store the perf buffer pointers in a vector of unique_ptrs.
    // When open_perf_buffers_ is cleared or destroyed,
    // perf_reader_free is automatically called.
    open_perf_buffers_.emplace_back(reader, perf_reader_free);

    struct epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.ptr = reader;
    int reader_fd = perf_reader_fd((perf_reader*)reader);

    bpf_update_elem(
        maps[MapManager::Type::PerfEvent].value()->mapfd_, &cpu, &reader_fd, 0);
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, reader_fd, &ev) == -1)
    {
      LOG(ERROR) << "Failed to add perf reader to epoll";
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
    if ((procmon_ && !procmon_->is_alive()) || (child_ && !child_->is_alive()))
    {
      return;
    }
  }
  return;
}

int BPFtrace::print_maps()
{
  for (auto &mapmap : maps)
  {
    int err = print_map(*mapmap.get(), 0, 0);
    if (err)
      return err;
  }

  return 0;
}

// clear a map
int BPFtrace::clear_map(IMap &map)
{
  if (!map.is_clearable())
    return zero_map(map);

  std::vector<uint8_t> old_key;
  try
  {
    if (map.type_.IsHistTy() || map.type_.IsLhistTy() ||
        map.type_.IsStatsTy() || map.type_.IsAvgTy())
      // hist maps have 8 extra bytes for the bucket number
      old_key = find_empty_key(map, map.key_.size() + 8);
    else
      old_key = find_empty_key(map, map.key_.size());
  }
  catch (std::runtime_error &e)
  {
    LOG(ERROR) << "failed to get key for map '" << map.name_
               << "': " << e.what();
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
      LOG(ERROR) << "failed to look up elem: " << err;
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
    if (map.type_.IsHistTy() || map.type_.IsLhistTy() ||
        map.type_.IsStatsTy() || map.type_.IsAvgTy())
      // hist maps have 8 extra bytes for the bucket number
      old_key = find_empty_key(map, map.key_.size() + 8);
    else
      old_key = find_empty_key(map, map.key_.size());
  }
  catch (std::runtime_error &e)
  {
    LOG(ERROR) << "failed to get key for map '" << map.name_
               << "': " << e.what();
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

  int value_size = map.type_.GetSize() * nvalues;
  std::vector<uint8_t> zero(value_size, 0);
  for (auto &key : keys)
  {
    int err = bpf_update_elem(map.mapfd_, key.data(), zero.data(), BPF_EXIST);

    if (err)
    {
      LOG(ERROR) << "failed to look up elem: " << err;
      return -1;
    }
  }

  return 0;
}

std::string BPFtrace::map_value_to_str(const SizedType &stype,
                                       std::vector<uint8_t> value,
                                       bool is_per_cpu,
                                       uint32_t div)
{
  uint32_t nvalues = is_per_cpu ? ncpus_ : 1;
  if (stype.IsKstackTy())
    return get_stack(
        read_data<uint64_t>(value.data()), false, stype.stack_type, 8);
  else if (stype.IsUstackTy())
    return get_stack(
        read_data<uint64_t>(value.data()), true, stype.stack_type, 8);
  else if (stype.IsKsymTy())
    return resolve_ksym(read_data<uintptr_t>(value.data()));
  else if (stype.IsUsymTy())
    return resolve_usym(read_data<uintptr_t>(value.data()),
                        read_data<uintptr_t>(value.data() + 8));
  else if (stype.IsInetTy())
    return resolve_inet(read_data<uint64_t>(value.data()),
                        (uint8_t *)(value.data() + 8));
  else if (stype.IsUsernameTy())
    return resolve_uid(read_data<uint64_t>(value.data()));
  else if (stype.IsBufferTy())
    return resolve_buf(reinterpret_cast<char *>(value.data() + 1),
                       *reinterpret_cast<uint8_t *>(value.data()));
  else if (stype.IsStringTy())
  {
    auto p = reinterpret_cast<const char *>(value.data());
    return std::string(p, strnlen(p, stype.GetSize()));
  }
  else if (stype.IsCountTy())
    return std::to_string(reduce_value<uint64_t>(value, nvalues) / div);
  else if (stype.IsIntTy())
  {
    auto sign = stype.IsSigned();
    switch (stype.GetIntBitWidth())
    {
      // clang-format off
      case 64:
        if (sign)
          return std::to_string(
            reduce_value<int64_t>(value, nvalues) / (int64_t)div);
        return std::to_string(reduce_value<uint64_t>(value, nvalues) / div);
      case 32:
        if (sign)
          return std::to_string(
            reduce_value<int32_t>(value, nvalues) / (int32_t)div);
        return std::to_string(reduce_value<uint32_t>(value, nvalues) / div);
      case 16:
        if (sign)
          return std::to_string(
            reduce_value<int16_t>(value, nvalues) / (int16_t)div);
        return std::to_string(reduce_value<uint16_t>(value, nvalues) / div);
      case 8:
        if (sign)
          return std::to_string(
            reduce_value<int8_t>(value, nvalues) / (int8_t)div);
        return std::to_string(reduce_value<uint8_t>(value, nvalues) / div);
        // clang-format on
      default:
        LOG(FATAL) << "map_value_to_str: Invalid int bitwidth: "
                   << stype.GetIntBitWidth() << "provided";
        return {};
    }
    // lgtm[cpp/missing-return]
  }
  else if (stype.IsSumTy() || stype.IsIntTy())
  {
    if (stype.IsSigned())
      return std::to_string(reduce_value<int64_t>(value, nvalues) / div);

    return std::to_string(reduce_value<uint64_t>(value, nvalues) / div);
  }
  else if (stype.IsMinTy())
    return std::to_string(min_value(value, nvalues) / div);
  else if (stype.IsMaxTy())
    return std::to_string(max_value(value, nvalues) / div);
  else if (stype.IsProbeTy())
    return resolve_probe(read_data<uint64_t>(value.data()));
  else if (stype.IsTimestampTy())
    return resolve_timestamp(
        reinterpret_cast<AsyncEvent::Strftime *>(value.data())->strftime_id,
        reinterpret_cast<AsyncEvent::Strftime *>(value.data())
            ->nsecs_since_boot);
  else
    return std::to_string(read_data<int64_t>(value.data()) / div);
}

int BPFtrace::print_map(IMap &map, uint32_t top, uint32_t div)
{
  if (map.type_.IsHistTy() || map.type_.IsLhistTy())
    return print_map_hist(map, top, div);
  else if (map.type_.IsAvgTy() || map.type_.IsStatsTy())
    return print_map_stats(map, top, div);

  uint32_t nvalues = map.is_per_cpu_type() ? ncpus_ : 1;
  std::vector<uint8_t> old_key;
  try
  {
    old_key = find_empty_key(map, map.key_.size());
  }
  catch (std::runtime_error &e)
  {
    LOG(ERROR) << "failed to get key for map '" << map.name_
               << "': " << e.what();
    return -2;
  }
  auto key(old_key);

  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> values_by_key;

  while (bpf_get_next_key(map.mapfd_, old_key.data(), key.data()) == 0)
  {
    int value_size = map.type_.GetSize();
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
      LOG(ERROR) << "failed to look up elem: " << err;
      return -1;
    }

    values_by_key.push_back({key, value});

    old_key = key;
  }

  if (map.type_.IsCountTy() || map.type_.IsSumTy() || map.type_.IsIntTy())
  {
    bool is_signed = map.type_.IsSigned();
    std::sort(values_by_key.begin(), values_by_key.end(), [&](auto &a, auto &b)
    {
      if (is_signed)
        return reduce_value<int64_t>(a.second, nvalues) < reduce_value<int64_t>(b.second, nvalues);
      return reduce_value<uint64_t>(a.second, nvalues) < reduce_value<uint64_t>(b.second, nvalues);
    });
  }
  else if (map.type_.IsMinTy())
  {
    std::sort(values_by_key.begin(), values_by_key.end(), [&](auto &a, auto &b)
    {
      return min_value(a.second, nvalues) < min_value(b.second, nvalues);
    });
  }
  else if (map.type_.IsMaxTy())
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
    LOG(ERROR) << "failed to get key for map '" << map.name_
               << "': " << e.what();
    return -2;
  }
  auto key(old_key);

  std::map<std::vector<uint8_t>, std::vector<uint64_t>> values_by_key;

  while (bpf_get_next_key(map.mapfd_, old_key.data(), key.data()) == 0)
  {
    auto key_prefix = std::vector<uint8_t>(map.key_.size());
    uint64_t bucket = read_data<uint64_t>(key.data() + map.key_.size());

    for (size_t i=0; i<map.key_.size(); i++)
      key_prefix.at(i) = key.at(i);

    int value_size = map.type_.GetSize() * nvalues;
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
      LOG(ERROR) << "failed to look up elem: " << err;
      return -1;
    }

    if (values_by_key.find(key_prefix) == values_by_key.end())
    {
      // New key - create a list of buckets for it
      if (map.type_.IsHistTy())
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
    int64_t sum = 0;
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

int BPFtrace::print_map_stats(IMap &map, uint32_t top, uint32_t div)
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
    LOG(ERROR) << "failed to get key for map '" << map.name_
               << "': " << e.what();
    return -2;
  }
  auto key(old_key);

  std::map<std::vector<uint8_t>, std::vector<int64_t>> values_by_key;

  while (bpf_get_next_key(map.mapfd_, old_key.data(), key.data()) == 0)
  {
    auto key_prefix = std::vector<uint8_t>(map.key_.size());
    uint64_t bucket = read_data<uint64_t>(key.data() + map.key_.size());

    for (size_t i=0; i<map.key_.size(); i++)
      key_prefix.at(i) = key.at(i);

    int value_size = map.type_.GetSize() * nvalues;
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
      LOG(ERROR) << "failed to look up elem: " << err;
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

  if (div == 0)
    div = 1;
  out_->map_stats(*this, map, top, div, values_by_key, total_counts_by_key);
  return 0;
}

template <typename T>
T BPFtrace::reduce_value(const std::vector<uint8_t> &value, int nvalues)
{
  T sum = 0;
  for (int i=0; i<nvalues; i++)
  {
    sum += read_data<T>(value.data() + i * sizeof(T));
  }
  return sum;
}

uint64_t BPFtrace::max_value(const std::vector<uint8_t> &value, int nvalues)
{
  uint64_t val, max = 0;
  for (int i=0; i<nvalues; i++)
  {
    val = read_data<uint64_t>(value.data() + i * sizeof(uint64_t));
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
    val = read_data<int64_t>(value.data() + i * sizeof(int64_t));
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
  // 4.12 and above kernel supports passing NULL to BPF_MAP_GET_NEXT_KEY
  // to get first key of the map. For older kernels, the call will fail.
  if (size == 0) size = 8;
  auto key = std::vector<uint8_t>(size);
  uint32_t nvalues = map.is_per_cpu_type() ? ncpus_ : 1;
  int value_size = map.type_.GetSize() * nvalues;
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
  int err = bpf_lookup_elem(maps[stack_type].value()->mapfd_,
                            &stackid,
                            stack_trace.data());
  if (err)
  {
    // ignore EFAULT errors: eg, kstack used but no kernel stack
    if (stackid != -EFAULT)
      LOG(ERROR) << "failed to look up stack id " << stackid << " (pid " << pid
                 << "): " << err;
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
    LOG(ERROR) << strerror(errno) << ": " << file_name;
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

std::string BPFtrace::resolve_timestamp(uint32_t strftime_id,
                                        uint64_t nsecs_since_boot)
{
  if (!boottime_)
  {
    LOG(ERROR) << "Cannot resolve timestamp due to failed boot time calcuation";
    return "(?)";
  }
  auto fmt = strftime_args_[strftime_id].c_str();
  char timestr[STRING_SIZE];
  struct tm tmp;
  time_t time = boottime_->tv_sec +
                ((boottime_->tv_nsec + nsecs_since_boot) / 1e9);
  if (!localtime_r(&time, &tmp))
  {
    LOG(ERROR) << "localtime_r: " << strerror(errno);
    return "(?)";
  }
  if (strftime(timestr, sizeof(timestr), fmt, &tmp) == 0)
  {
    LOG(ERROR) << "strftime returned 0";
    return "(?)";
  }
  return timestr;
}

std::string BPFtrace::resolve_buf(char *buf, size_t size)
{
  return hex_format_buffer(buf, size);
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
    LOG(ERROR) << strerror(errno) << ": " << file_name;
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
  auto syms = static_cast<std::set<std::string> *>(payload);
  syms->insert(std::string(symname));
  return 0;
}
#endif

std::string BPFtrace::extract_func_symbols_from_path(const std::string &path) const
{
  std::vector<std::string> real_paths;
  if (path.find('*') != std::string::npos)
    real_paths = resolve_binary_path(path);
  else
    real_paths.push_back(path);
#ifdef HAVE_BCC_ELF_FOREACH_SYM
  struct bcc_symbol_option symbol_option;
  memset(&symbol_option, 0, sizeof(symbol_option));
  symbol_option.use_debug_file = 1;
  symbol_option.check_debug_file_crc = 1;
  symbol_option.use_symbol_type = (1 << STT_FUNC) | (1 << STT_GNU_IFUNC);
#endif

  std::string result;
  for (auto &real_path : real_paths)
  {
    std::set<std::string> syms;
#ifdef HAVE_BCC_ELF_FOREACH_SYM
    // Workaround: bcc_elf_foreach_sym() can return the same symbol twice if
    // it's also found in debug info (#1138), so a std::set is used here (and in
    // the add_symbol callback) to ensure that each symbol will be unique in the
    // returned string.
    int err = bcc_elf_foreach_sym(
        real_path.c_str(), add_symbol, &symbol_option, &syms);
    if (err)
    {
      LOG(WARNING) << "Could not list function symbols: " + real_path;
    }
#else
    std::string call_str = std::string("objdump -tT ") + real_path + +" | " +
                           "grep \"F .text\" | grep -oE '[^[:space:]]+$'";
    const char *call = call_str.c_str();
    std::istringstream iss(exec_system(call));
    std::copy(std::istream_iterator<std::string>(iss),
              std::istream_iterator<std::string>(),
              std::inserter(syms, syms.begin()));
#endif
    for (auto &sym : syms)
      result += real_path + ":" + sym + "\n";
  }
  return result;
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
  }

  // TODO(mmarchini): handle inet_ntop errors
  return addrstr;
}

// /proc/sys/kernel/randomize_va_space >= 1 and        // system-wide
// (/proc/<pid>/personality & ADDR_NO_RNDOMIZE) == 0   // this pid
// if pid == -1, then only check system-wide setting
bool BPFtrace::is_aslr_enabled(int pid)
{
  std::string randomize_va_space_file = "/proc/sys/kernel/randomize_va_space";
  std::string personality_file = "/proc/" + std::to_string(pid) +
                                 "/personality";

  {
    std::ifstream file(randomize_va_space_file);
    if (file.fail())
    {
      if (bt_verbose)
        LOG(ERROR) << strerror(errno) << ": " << randomize_va_space_file;
      // conservatively return true
      return true;
    }

    std::string line;
    if (std::getline(file, line) && std::stoi(line) < 1)
      return false;
  }

  if (pid == -1)
    return true;

  {
    std::ifstream file(personality_file);
    if (file.fail())
    {
      if (bt_verbose)
        LOG(ERROR) << strerror(errno) << ": " << personality_file;
      return true;
    }
    std::string line;
    if (std::getline(file, line) &&
        ((std::stoi(line) & ADDR_NO_RANDOMIZE) == 0))
      return true;
  }

  return false;
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
    if (cache_user_symbols_)
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
    else
    {
      psyms = bcc_symcache_new(pid, &symopts);
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

  if (psyms && !cache_user_symbols_)
    bcc_free_symcache(psyms, pid);

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
    arg_offset += arg.GetSize();
  }

  // Sort the key arguments in reverse order so the results are sorted by
  // the first argument first, then the second, etc.
  for (size_t i=key_args.size(); i-- > 0; )
  {
    auto arg = key_args.at(i);
    arg_offset -= arg.GetSize();

    if (arg.IsIntTy())
    {
      if (arg.GetSize() == 8)
      {
        std::stable_sort(
            values_by_key.begin(), values_by_key.end(), [&](auto &a, auto &b) {
              auto va = read_data<uint64_t>(a.first.data() + arg_offset);
              auto vb = read_data<uint64_t>(b.first.data() + arg_offset);
              return va < vb;
            });
      }
      else if (arg.GetSize() == 4)
      {
        std::stable_sort(
            values_by_key.begin(), values_by_key.end(), [&](auto &a, auto &b) {
              auto va = read_data<uint32_t>(a.first.data() + arg_offset);
              auto vb = read_data<uint32_t>(b.first.data() + arg_offset);
              return va < vb;
            });
      }
      else
      {
        LOG(FATAL) << "invalid integer argument size. 4 or 8  expected, but "
                   << arg.GetSize() << " provided";
      }

    }
    else if (arg.IsStringTy())
    {
      std::stable_sort(
          values_by_key.begin(), values_by_key.end(), [&](auto &a, auto &b) {
            return strncmp((const char *)(a.first.data() + arg_offset),
                           (const char *)(b.first.data() + arg_offset),
                           arg.GetSize()) < 0;
          });
    }

    // Other types don't get sorted
  }
}

std::string BPFtrace::get_string_literal(const ast::Expression *expr) const
{
  if (expr->is_literal)
  {
    if (auto *string = dynamic_cast<const ast::String *>(expr))
      return string->str;
    else if (auto *str_call = dynamic_cast<const ast::Call *>(expr))
    {
      // Positional parameters in the form str($1) can be used as literals
      if (str_call->func == "str")
      {
        if (auto *pos_param = dynamic_cast<const ast::PositionalParameter *>(
                str_call->vargs->at(0)))
          return get_param(pos_param->n, true);
      }
    }
  }

  LOG(ERROR) << "Expected string literal, got " << expr->type;
  return "";
}

} // namespace bpftrace
