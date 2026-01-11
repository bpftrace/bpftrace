#include <filesystem>
#include <getopt.h>
#include <iostream>
#include <string>

#include "aot.h"
#include "bpftrace.h"
#include "log.h"
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
}

int main(int argc, char* argv[])
{
  std::string output_file, output_format;
  int c;

  std::vector<std::string> named_params;

  // TODO: which other options from `bpftrace` should be included?
  const char* const short_opts = "d:f:hVo:qv";
  option long_opts[] = {
    option{
        .name = "help",
        .has_arg = no_argument,
        .flag = nullptr,
        .val = 'h',
    },
    option{
        .name = "version",
        .has_arg = no_argument,
        .flag = nullptr,
        .val = 'V',
    },
    // Must be last
    option{
        .name = nullptr,
        .has_arg = 0,
        .flag = nullptr,
        .val = 0,
    },
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
        if (std::string(optarg) == "libbpf")
          bt_debug.insert(DebugStage::Libbpf);
        else if (std::string(optarg) == "verifier")
          bt_debug.insert(DebugStage::Verifier);
        else if (std::string(optarg) == "all") {
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

  while (optind < argc) {
    auto pos_arg = std::string(argv[optind]);
    if (pos_arg.starts_with("--")) {
      named_params.emplace_back(pos_arg.substr(2));
    } else {
      // AOT does not support positional parameters
      LOG(ERROR) << "AOT does not support positional parameters";
      return 1;
    }
    optind++;
  }

  if (argv[optind]) {
    usage(std::cerr, argv[0]);
    return 1;
  }

  check_privileges();

  libbpf_set_print(libbpf_print);

  auto ok = BPFtrace::create();
  if (!ok) {
    LOG(ERROR) << "Failed to create BPFtrace: " << ok.takeError();
    return 1;
  }
  auto bpftrace = std::move(*ok);

  int err = aot::load(*bpftrace, argv[0]);
  if (err) {
    LOG(ERROR) << "Failed to load AOT script";
    return err;
  }

  // FIXME(#4087): We should serialize the C enum definitions as part of the AOT
  // payload in order to allow this printing to work.
  ast::CDefinitions no_c_defs;

  return run_bpftrace(*bpftrace,
                      output_file,
                      output_format,
                      no_c_defs,
                      bpftrace->bytecode_,
                      std::move(named_params));
}
