#include <csignal>
#include <cstring>
#include <fstream>
#include <linux/version.h>
#include <optional>
#include <sys/utsname.h>

#include "log.h"
#include "output/json.h"
#include "output/text.h"
#include "run_bpftrace.h"
#include "types_format.h"
#include "util/kernel.h"
#include "version.h"

using namespace bpftrace;

static const char *libbpf_print_level_string(enum libbpf_print_level level)
{
  switch (level) {
    case LIBBPF_WARN:
      return "WARN";
    case LIBBPF_INFO:
      return "INFO";
    default:
      return "DEBUG";
  }
}

int libbpf_print(enum libbpf_print_level level, const char *msg, va_list ap)
{
  if (!bt_debug.contains(DebugStage::Libbpf))
    return 0;

  printf("[%s] ", libbpf_print_level_string(level));
  return vprintf(msg, ap);
}

void check_is_root()
{
  if (geteuid() != 0) {
    LOG(ERROR) << "bpftrace currently only supports running as the root user.";
    exit(1);
  }
}

// Simple forwarding streambuf that can flush on-demand.
namespace {
class flushing_streambuf : public std::streambuf {
public:
  flushing_streambuf(std::streambuf *dest,
                     bool flush_always,
                     bool flush_on_newline)
      : dest_(dest),
        flush_always_(flush_always),
        flush_on_newline_(flush_on_newline)
  {
  }

protected:
  int_type overflow(int_type ch) override
  {
    if (traits_type::eq_int_type(ch, traits_type::eof()))
      return dest_->sputc(ch);

    auto res = dest_->sputc(traits_type::to_char_type(ch));
    if (flush_always_ || (flush_on_newline_ && ch == '\n'))
      dest_->pubsync();
    return res;
  }

  std::streamsize xsputn(const char *s, std::streamsize n) override
  {
    auto res = dest_->sputn(s, n);
    if (res > 0) {
      if (flush_always_) {
        dest_->pubsync();
      } else if (flush_on_newline_) {
        // Flush if any newline was written
        if (std::memchr(s, '\n', static_cast<size_t>(res)) != nullptr)
          dest_->pubsync();
      }
    }
    return res;
  }

  int sync() override
  {
    return dest_->pubsync();
  }

private:
  std::streambuf *dest_;
  bool flush_always_;
  bool flush_on_newline_;
};
} // namespace

int run_bpftrace(BPFtrace &bpftrace,
                 const std::string &output_file,
                 const std::string &output_format,
                 const ast::CDefinitions &c_definitions,
                 BpfBytecode &bytecode,
                 std::vector<std::string> &&named_params,
                 bool out_flush_always,
                 bool out_flush_on_newline)
{
  int err;

  auto k_version = util::kernel_version(util::KernelVersionMethod::UTS);
  auto min_k_version = static_cast<uint32_t>(
      KERNEL_VERSION(MIN_KERNEL_VERSION_MAJOR,
                     MIN_KERNEL_VERSION_MINOR,
                     MIN_KERNEL_VERSION_PATCH));

  if (k_version < min_k_version) {
    struct utsname utsname;
    uname(&utsname);

    LOG(WARNING) << "Kernel version (" << utsname.release
                 << ") is lower than the minimum supported kernel version ("
                 << MIN_KERNEL_VERSION_MAJOR << "." << MIN_KERNEL_VERSION_MINOR
                 << "." << MIN_KERNEL_VERSION_PATCH
                 << "). Some features/scripts may not work as expected.";
  }

  // Process all arguments.
  auto named_param_vals = bpftrace.resources.global_vars.get_named_param_vals(
      named_params);
  if (!named_param_vals) {
    auto ok = handleErrors(std::move(named_param_vals),
                           [&](const globalvars::UnknownParamError &uo_err) {
                             LOG(ERROR) << uo_err.err();
                             auto hint = uo_err.hint();
                             if (!hint.empty()) {
                               LOG(HINT) << hint;
                             }
                           });
    if (!ok) {
      LOG(ERROR) << ok.takeError();
    }
    return 1;
  }
  bytecode.update_global_vars(bpftrace, std::move(*named_param_vals));

  // Create our output.
  std::ostream *os = &std::cout;
  std::ofstream outputstream;
  if (!output_file.empty()) {
    outputstream.open(output_file);
    if (outputstream.fail()) {
      LOG(ERROR) << "Failed to open output file: \"" << output_file
                 << "\": " << strerror(errno);
      return 1;
    }
    os = &outputstream;
  }
  std::unique_ptr<output::Output> output;

  // Optionally wrap the output stream to control flushing behavior.
  // Keep these local so their lifetime covers the entire execution.
  std::optional<flushing_streambuf> fsb;
  std::optional<std::ostream> wrapped_os;
  if (out_flush_always || out_flush_on_newline) {
    fsb.emplace(os->rdbuf(), out_flush_always, out_flush_on_newline);
    wrapped_os.emplace(&*fsb);
    os = &wrapped_os.value();
  }
  if (output_format.empty() || output_format == "text") {
    // Note that there are two parameters here: we leave the err output as
    // std::cerr, so this can be seen while running.
    output = std::make_unique<output::TextOutput>(*os);
  } else if (output_format == "json") {
    output = std::make_unique<output::JsonOutput>(*os);
  } else {
    LOG(ERROR) << "Invalid output format \"" << output_format << "\"\n"
               << "Valid formats: 'text', 'json'";
    return 1;
  }

  // Signal handler that lets us know an exit signal was received.
  struct sigaction act = {};
  act.sa_handler = [](int) { BPFtrace::exitsig_recv = true; };
  sigaction(SIGINT, &act, nullptr);
  sigaction(SIGTERM, &act, nullptr);

  // Signal handler that prints all maps when SIGUSR1 was received.
  act.sa_handler = [](int) { BPFtrace::sigusr1_recv = true; };
  sigaction(SIGUSR1, &act, nullptr);

  err = bpftrace.run(*output, c_definitions, std::move(bytecode));
  if (err)
    return err;

  // Indicate that we are done the main loop.
  output->end();

  // We are now post-processing. If we receive another SIGINT,
  // handle it normally (exit)
  act.sa_handler = SIG_DFL;
  sigaction(SIGINT, &act, nullptr);

  // Print maps if needed (true by default).
  if (!dry_run) {
    if (bpftrace.run_benchmarks_) {
      output->benchmark_results(bpftrace.benchmark_results);
    }
    if (bpftrace.config_->print_maps_on_exit) {
      for (const auto &[_, map] : bpftrace.bytecode_.maps()) {
        if (!map.is_printable())
          continue;
        auto res = format(bpftrace, c_definitions, map);
        if (!res) {
          std::cerr << "Error printing map: " << res.takeError();
          continue;
        }
        output->map(map.name(), *res);
      }
    }
  }

  if (bpftrace.child_) {
    auto val = 0;
    if ((val = bpftrace.child_->term_signal()) > -1)
      LOG(V1) << "Child terminated by signal: " << val;
    if ((val = bpftrace.child_->exit_code()) > -1)
      LOG(V1) << "Child exited with code: " << val;
  }

  if (err)
    return err;

  return BPFtrace::exit_code;
}
