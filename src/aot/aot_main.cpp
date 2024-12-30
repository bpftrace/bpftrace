#include <filesystem>
#include <fstream>
#include <getopt.h>
#include <iostream>

#include "aot.h"
#include "bpftrace.h"
#include "log.h"
#include "output.h"
#include "run_bpftrace.h"
#include "version.h"

using namespace bpftrace;

void usage(std::ostream& out, std::string_view filename)
{
  // clang-format off
  out << "USAGE: " << filename << " [options]" << std::endl;
  out << std::endl;
  out << "OPTIONS:" << std::endl;
  out << "    -f FORMAT      output format ('text', 'json')" << std::endl;
  out << "    -o file        redirect bpftrace output to file" << std::endl;
  out << "    -q,            keep messages quiet" << std::endl;
  out << "    -v,            verbose messages" << std::endl;
  out << "    -d STAGE       debug info for various stages of bpftrace execution" << std::endl;
  out << "                   ('all', 'libbpf', 'verifier')" << std::endl;
  out << "    -h, --help     show this help message" << std::endl;
  out << "    -V, --version  bpftrace version" << std::endl;
  out << std::endl;
  // clang-format on
  return;
}

std::unique_ptr<Output> prepare_output(const std::string& output_file,
                                       const std::string& output_format)
{
  std::ostream* os = &std::cout;
  std::ofstream outputstream;
  if (!output_file.empty()) {
    outputstream.open(output_file);
    if (outputstream.fail()) {
      LOG(ERROR) << "Failed to open output file: \"" << output_file
                 << "\": " << strerror(errno);
      return nullptr;
    }
    os = &outputstream;
  }

  std::unique_ptr<Output> output;
  if (output_format.empty() || output_format == "text") {
    output = std::make_unique<TextOutput>(*os);
  } else if (output_format == "json") {
    output = std::make_unique<JsonOutput>(*os);
  } else {
    LOG(ERROR) << "Invalid output format \"" << output_format << "\"\n"
               << "Valid formats: 'text', 'json'";
    return nullptr;
  }

  return output;
}

int main(int argc, char* argv[])
{
  std::string output_file, output_format;
  int c;

  // TODO: which other options from `bpftrace` should be included?
  const char* const short_opts = "d:f:hVo:qv";
  option long_opts[] = {
    option{ "help", no_argument, nullptr, 'h' },
    option{ "version", no_argument, nullptr, 'V' },
    option{ nullptr, 0, nullptr, 0 }, // Must be last
  };

  std::filesystem::path p(argv[0]);
  if (p.filename() == aot::AOT_SHIM_NAME) {
    LOG(ERROR) << "Runtime shim should not be run directly, please generate a "
                  "binary using --aot option in bpftrace";
    return 1;
  }

  while ((c = getopt_long(argc, argv, short_opts, long_opts, nullptr)) != -1) {
    switch (c) {
      case 'o':
        output_file = optarg;
        break;
      case 'f':
        output_format = optarg;
        break;
      case 'h':
        usage(std::cout, argv[0]);
        return 0;
      case 'V':
        std::cout << "bpftrace " << BPFTRACE_VERSION << std::endl;
        return 0;
      case 'q':
        bt_quiet = true;
        break;
      case 'v':
        bt_verbose = true;
        break;
      case 'd':
        if (std::strcmp(optarg, "libbpf") == 0)
          bt_debug.insert(DebugStage::Libbpf);
        else if (std::strcmp(optarg, "verifier") == 0)
          bt_debug.insert(DebugStage::Verifier);
        else if (std::strcmp(optarg, "all") == 0) {
          bt_debug.insert({ DebugStage::Libbpf, DebugStage::Verifier });
        } else {
          LOG(ERROR) << "USAGE: invalid option for -d: " << optarg;
          return 1;
        }
        break;
      default:
        usage(std::cerr, argv[0]);
        return 1;
    }
  }

  if (argv[optind]) {
    usage(std::cerr, argv[0]);
    return 1;
  }

  check_is_root();

  libbpf_set_print(libbpf_print);

  auto output = prepare_output(output_file, output_format);
  if (!output)
    return 1;

  BPFtrace bpftrace(std::move(output));

  int err = aot::load(bpftrace, argv[0]);
  if (err) {
    LOG(ERROR) << "Failed to load AOT script";
    return err;
  }

  return run_bpftrace(bpftrace, bpftrace.bytecode_);
}
