#include <csignal>
#include <fstream>

#include "log.h"
#include "output/json.h"
#include "output/text.h"
#include "run_bpftrace.h"
#include "types_format.h"

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

int run_bpftrace(BPFtrace &bpftrace,
                 const std::string &output_file,
                 const std::string &output_format,
                 const ast::CDefinitions &c_definitions,
                 BpfBytecode &bytecode)
{
  int err;

  // Check for required features.
  if (!bpftrace.feature_->has_map_ringbuf()) {
    LOG(ERROR) << "Your kernel is too old and is missing the "
                  "BPF_MAP_TYPE_RINGBUF, which bpftrace requires.";
    return 1;
  }

  // Create our output.
  std::ostream *os = &std::cout;
  std::ofstream outputstream;
  if (!output_file.empty()) {
    outputstream.open(output_file);
    if (outputstream.fail()) {
      LOG(ERROR) << "Failed to open output file: \"" << output_file
                 << "\": " << strerror(errno);
      exit(1);
    }
    os = &outputstream;
  }
  std::unique_ptr<output::Output> output;
  if (output_format == "" || output_format == "text") {
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

  err = bpftrace.run(*output.get(), c_definitions, std::move(bytecode));
  if (err)
    return err;

  // Indicate that we are done the main loop.
  output->end();

  // We are now post-processing. If we receive another SIGINT,
  // handle it normally (exit)
  act.sa_handler = SIG_DFL;
  sigaction(SIGINT, &act, nullptr);

  // Print maps if needed (true by default).
  if (!dry_run && bpftrace.config_->print_maps_on_exit) {
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
