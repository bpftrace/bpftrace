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
#include <signal.h>
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
#ifdef HAVE_LIBBPF_BPF_H
#include <bpf/bpf.h>
#endif

#include "ast/async_event_types.h"
#include "bpftrace.h"
#include "log.h"
#include "printf.h"
#include "relocator.h"
#include "resolve_cgroupid.h"
#include "triggers.h"
#include "utils.h"

namespace libbpf {
#define __BPF_NAME_FN(x) #x
const char *bpf_func_name[] = { __BPF_FUNC_MAPPER(__BPF_NAME_FN) };
#undef __BPF_NAME_FN
} // namespace libbpf

namespace bpftrace {

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

Probe BPFtrace::generateWatchpointSetupProbe(const std::string &func,
                                             const ast::AttachPoint &ap,
                                             const ast::Probe &probe)
{
  Probe setup_probe;
  setup_probe.name = get_watchpoint_setup_probe_name(ap.name(func));
  setup_probe.type = ProbeType::uprobe;
  setup_probe.path = ap.target;
  setup_probe.attach_point = func;
  setup_probe.orig_name = get_watchpoint_setup_probe_name(probe.name());
  setup_probe.index = ap.index(func) > 0 ? ap.index(func) : probe.index();

  return setup_probe;
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
        matches = probe_matcher_->get_matches_for_ap(*attach_point);
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
              probetype(attach_point->provider) == ProbeType::uretprobe ||
              probetype(attach_point->provider) == ProbeType::watchpoint ||
              probetype(attach_point->provider) ==
                  ProbeType::asyncwatchpoint) &&
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
        matches = probe_matcher_->get_matches_for_ap(*attach_point);
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

    // You may notice that the below loop is somewhat duplicated in
    // codegen_llvm.cpp. The reason is because codegen tries to avoid
    // generating duplicate programs if it can be avoided. For example, a
    // program `kprobe:do_* { print("hi") }` can be generated once and reused
    // for multiple attachpoints. Thus, we need this loop here to attach the
    // single program to multiple attach points.
    //
    // There may be a way to refactor and unify the codepaths in a clean manner
    // but so far it has eluded your author.
    for (const auto &f : attach_funcs)
    {
      std::string func = f;
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
      else if (probetype(attach_point->provider) == ProbeType::watchpoint ||
               probetype(attach_point->provider) == ProbeType::asyncwatchpoint)
      {
        target = erase_prefix(func_id);
        erase_prefix(func);
      }
      else if (probetype(attach_point->provider) == ProbeType::iter)
      {
        has_iter_ = true;
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
      probe.async = attach_point->async;
      probe.pin = attach_point->pin;

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
      else if ((probetype(attach_point->provider) == ProbeType::watchpoint ||
                probetype(attach_point->provider) ==
                    ProbeType::asyncwatchpoint) &&
               attach_point->func.size())
      {
        probes_.emplace_back(
            generateWatchpointSetupProbe(func_id, *attach_point, p));

        watchpoint_probes_.emplace_back(std::move(probe));
      }
      else
      {
        probes_.push_back(probe);
      }
    }
  }

  return 0;
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
    const SizedType &ty = bpftrace->resources.non_map_print_args.at(
        print->print_id);

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
    auto fmt = bpftrace->resources.time_args[time->time_id].c_str();
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
    auto delim = bpftrace->resources.join_args[join_id].c_str();
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
    auto &info = bpftrace->resources.helper_error_info[error_id];
    std::stringstream msg;
    msg << "Failed to " << libbpf::bpf_func_name[info.func_id] << ": ";
    if (return_value < 0)
      msg << strerror(-return_value) << " (" << return_value << ")";
    else
      msg << return_value;
    LOG(WARNING, info.loc, std::cerr) << msg.str();
    return;
  }
  else if (printf_id == asyncactionint(AsyncAction::watchpoint_attach))
  {
    bool abort = false;
    auto watchpoint = static_cast<AsyncEvent::Watchpoint *>(data);
    uint64_t probe_idx = watchpoint->watchpoint_idx;
    uint64_t addr = watchpoint->addr;

    if (probe_idx >= bpftrace->watchpoint_probes_.size())
    {
      std::cerr << "Invalid watchpoint probe idx=" << probe_idx << std::endl;
      abort = true;
      goto out;
    }

    // Ignore duplicate watchpoints (idx && addr same), but allow the same
    // address to be watched by different probes.
    //
    // NB: this check works b/c we set Probe::addr below
    //
    // TODO: Should we be printing a warning or info message out here?
    if (bpftrace->watchpoint_probes_[probe_idx].address == addr)
      goto out;

    // Attach the real watchpoint probe
    {
      bool registers_available = true;
      Probe &wp_probe = bpftrace->watchpoint_probes_[probe_idx];
      wp_probe.address = addr;
      std::vector<std::unique_ptr<AttachedProbe>> aps;
      try
      {
        aps = bpftrace->attach_probe(wp_probe, *bpftrace->bpforc_);
      }
      catch (const EnospcException &ex)
      {
        registers_available = false;
        bpftrace->out_->message(MessageType::lost_events,
                                "Failed to attach watchpoint probe. You are "
                                "out of watchpoint registers.");
        goto out;
      }

      if (aps.empty() && registers_available)
      {
        std::cerr << "Unable to attach real watchpoint probe" << std::endl;
        abort = true;
        goto out;
      }

      for (auto &ap : aps)
        bpftrace->attached_probes_.emplace_back(std::move(ap));
    }

  out:
    // Async watchpoints are not SIGSTOP'd
    if (bpftrace->watchpoint_probes_[probe_idx].async)
      return;

    // Let the tracee continue
    pid_t pid = bpftrace->child_
                    ? bpftrace->child_->pid()
                    : (bpftrace->procmon_ ? bpftrace->procmon_->pid() : -1);
    if (pid == -1 || ::kill(pid, SIGCONT) != 0)
    {
      std::cerr << "Failed to SIGCONT tracee: " << strerror(errno) << std::endl;
      abort = true;
    }

    if (abort)
      std::abort();

    return;
  }
  else if (printf_id == asyncactionint(AsyncAction::watchpoint_detach))
  {
    auto unwatch = static_cast<AsyncEvent::WatchpointUnwatch *>(data);
    uint64_t addr = unwatch->addr;

    // Remove all probes watching `addr`. Note how we fail silently here
    // (ie invalid addr). This lets script writers be a bit more aggressive
    // when unwatch'ing addresses, especially if they're sampling a portion
    // of addresses they're interested in watching.
    bpftrace->attached_probes_.erase(
        std::remove_if(bpftrace->attached_probes_.begin(),
                       bpftrace->attached_probes_.end(),
                       [&](const auto &ap) {
                         return ap->probe().address == addr;
                       }),
        bpftrace->attached_probes_.end());

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
    auto fmt = std::get<0>(bpftrace->resources.system_args[id]);
    auto args = std::get<1>(bpftrace->resources.system_args[id]);
    auto arg_values = bpftrace->get_arg_values(args, arg_data);

    bpftrace->out_->message(MessageType::syscall,
                            exec_system(format(fmt, arg_values).c_str()),
                            false);
    return;
  }
  else if ( printf_id >= asyncactionint(AsyncAction::cat))
  {
    auto id = printf_id - asyncactionint(AsyncAction::cat);
    auto fmt = std::get<0>(bpftrace->resources.cat_args[id]);
    auto args = std::get<1>(bpftrace->resources.cat_args[id]);
    auto arg_values = bpftrace->get_arg_values(args, arg_data);

    std::stringstream buf;
    cat_file(format(fmt, arg_values).c_str(), bpftrace->cat_bytes_max_, buf);
    bpftrace->out_->message(MessageType::cat, buf.str(), false);

    return;
  }

  // printf
  auto fmt = std::get<0>(bpftrace->resources.printf_args[printf_id]);
  auto args = std::get<1>(bpftrace->resources.printf_args[printf_id]);
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
      case Type::mac_address:
        arg_values.push_back(
            std::make_unique<PrintableString>(resolve_mac_address(
                reinterpret_cast<uint8_t *>(arg_data + arg.offset))));
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
    BpfOrc &bpforc)
{
  std::vector<std::unique_ptr<AttachedProbe>> ret;


  // use the single-probe program if it exists (as is the case with wildcards
  // and the name builtin, which must be expanded into separate programs per
  // probe), else try to find a the program based on the original probe name
  // that includes wildcards.
  auto usdt_location_idx = (probe.type == ProbeType::usdt)
                               ? std::make_optional<int>(
                                     probe.usdt_location_idx)
                               : std::nullopt;

  auto name = get_section_name_for_probe(probe.name,
                                         probe.index,
                                         usdt_location_idx);
  auto orig_name = get_section_name_for_probe(probe.orig_name,
                                              probe.index,
                                              usdt_location_idx);

  auto section = bpforc.getSection(name);
  if (!section)
  {
    section = bpforc.getSection(orig_name);
  }

  if (!section)
  {
    if (probe.name != probe.orig_name)
      LOG(ERROR) << "Code not generated for probe: " << probe.name
                 << " from: " << probe.orig_name;
    else
      LOG(ERROR) << "Code not generated for probe: " << probe.name;
    return ret;
  }

  // Make a copy of the bytecode and perform relocations
  //
  // We choose not to modify the original bytecode to void keeping
  // track of state when the same bytecode is attached to multiple probes.
  std::vector<uint8_t> relocated;
  relocated.reserve(std::get<1>(*section));
  memcpy(relocated.data(), std::get<0>(*section), std::get<1>(*section));
  std::get<0>(*section) = relocated.data();
  auto relocator = Relocator(*section, *this);
  if (relocator.relocate())
  {
    LOG(ERROR) << "Failed to relocate insns for probe: " << probe.name;
    return ret;
  }

  try
  {
    pid_t pid = child_ ? child_->pid() : this->pid();

    if (probe.type == ProbeType::usdt)
    {
      auto aps = attach_usdt_probe(probe, *section, pid, usdt_file_activation_);
      for (auto &ap : aps)
        ret.emplace_back(std::move(ap));

      return ret;
    }
    else if (probe.type == ProbeType::watchpoint ||
             probe.type == ProbeType::asyncwatchpoint)
    {
      ret.emplace_back(
          std::make_unique<AttachedProbe>(probe, *section, pid, *feature_));
      return ret;
    }
    else
    {
      ret.emplace_back(
          std::make_unique<AttachedProbe>(probe, *section, safe_mode_));
      return ret;
    }
  }
  catch (const EnospcException &e)
  {
    // Caller will handle
    throw e;
  }
  catch (const std::runtime_error &e)
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
    case ProbeType::iter:
      return true;
    case ProbeType::kretfunc:
    case ProbeType::kretprobe:
    case ProbeType::tracepoint:
    case ProbeType::profile:
    case ProbeType::interval:
    case ProbeType::watchpoint:
    case ProbeType::asyncwatchpoint:
    case ProbeType::hardware:
      return false;
    case ProbeType::invalid:
      LOG(FATAL) << "Unknown probe type";
  }

  return {}; // unreached
}

int BPFtrace::run_special_probe(std::string name,
                                BpfOrc &bpforc,
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

#ifdef HAVE_LIBBPF_LINK_CREATE
int BPFtrace::run_iter()
{
  auto probe = probes_.begin();
  char buf[1024] = {};
  ssize_t len;

  if (probe == probes_.end())
  {
    LOG(ERROR) << "Failed to create iter probe";
    return 1;
  }

  // If a script contains an iter probe, it must be the only probe
  assert(attached_probes_.size() == 1);
  if (attached_probes_.empty())
  {
    LOG(ERROR) << "Failed to attach iter probe";
    return 1;
  }

  auto &ap = *attached_probes_.begin();
  int link_fd = ap->linkfd_;
  if (link_fd < 0)
  {
    LOG(ERROR) << "Failed to link iter probe";
    return 1;
  }

  if (probe->pin.empty())
  {
    int iter_fd = bpf_iter_create(link_fd);

    if (iter_fd < 0)
    {
      LOG(ERROR) << "Failed to open iter probe link";
      return 1;
    }

    while ((len = read(iter_fd, buf, sizeof(buf))) > 0)
    {
      fwrite(buf, len, 1, stdout);
    }

    close(iter_fd);
  }
  else
  {
    auto pin = probe->pin;

    if (pin.at(0) != '/')
      pin = "/sys/fs/bpf/" + pin;

    if (bpf_obj_pin(link_fd, pin.c_str()))
      LOG(ERROR) << "Failed to pin iter probe link";
    else
      std::cout << "Program pinned to " << pin << std::endl;
  }

  return 0;
}
#else
int BPFtrace::run_iter()
{
  LOG(ERROR) << "iter is not available for linked bpf version";
  return 1;
}
#endif

int BPFtrace::run(std::unique_ptr<BpfOrc> bpforc)
{
  // Clear fake maps and replace with real maps
  maps = {};
  if (resources.create_maps(*this, false))
    return 1;

  bpforc_ = std::move(bpforc);

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

  if (run_special_probe("BEGIN_trigger", *bpforc_, BEGIN_trigger))
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
      auto aps = attach_probe(*probes, *bpforc_);

      if (aps.empty())
        return -1;

      for (auto &ap : aps)
        attached_probes_.emplace_back(std::move(ap));
    }
  }

  for (auto r_probes = probes_.rbegin(); r_probes != probes_.rend(); ++r_probes)
  {
    if (attach_reverse(*r_probes)) {
      auto aps = attach_probe(*r_probes, *bpforc_);

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

  if (has_iter_)
  {
    int err = run_iter();
    if (err)
      return err;
  }
  else
  {
    poll_perf_events(epollfd);
  }

  attached_probes_.clear();
  // finalize_ and exitsig_recv should be false from now on otherwise
  // perf_event_printer() can ignore the END_trigger() events.
  finalize_ = false;
  exitsig_recv = false;

  if (run_special_probe("END_trigger", *bpforc_, END_trigger))
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
    if (!mapmap->is_printable())
      continue;

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

std::optional<std::string> BPFtrace::get_watchpoint_binary_path() const
{
  if (child_)
  {
    // We can ignore all error checking here b/c child.cpp:validate_cmd() has
    // already done it
    auto args = split_string(cmd_, ' ', /* remove_empty= */ true);
    assert(!args.empty());
    return resolve_binary_path(args[0]).front();
  }
  else if (pid())
    return "/proc/" + std::to_string(pid()) + "/exe";
  else
  {
    return std::nullopt;
  }
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
  auto fmt = resources.strftime_args[strftime_id].c_str();
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

std::string BPFtrace::resolve_mac_address(const uint8_t *mac_addr) const
{
  const size_t SIZE = 18;
  char addr[SIZE];
  snprintf(addr,
           SIZE,
           "%02X:%02X:%02X:%02X:%02X:%02X",
           mac_addr[0],
           mac_addr[1],
           mac_addr[2],
           mac_addr[3],
           mac_addr[4],
           mac_addr[5]);
  return std::string(addr);
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
  assert(probe_id < resources.probe_ids.size());
  return resources.probe_ids[probe_id];
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

bool BPFtrace::is_traceable_func(const std::string &func_name) const
{
#ifdef FUZZ
  (void)func_name;
  return true;
#else
  return traceable_funcs_.find(func_name) != traceable_funcs_.end();
#endif
}

} // namespace bpftrace
