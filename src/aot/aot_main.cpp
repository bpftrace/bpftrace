#include <fstream>
#include <getopt.h>
#include <iostream>
#include <memory>

#include "aot.h"
#include "bpftrace.h"
#include "log.h"
#include "output.h"

using namespace bpftrace;

void usage()
{
  // clang-format off
  std::cerr << "USAGE: bpftrace-aotrt filename" << std::endl;
  std::cerr << std::endl;
  std::cerr << "OPTIONS:" << std::endl;
  std::cerr << "    -f FORMAT      output format ('text', 'json')" << std::endl;
  std::cerr << "    -o file        redirect bpftrace output to file" << std::endl;
  std::cerr << "    -v,            verbose messages" << std::endl;
  std::cerr << "    -h, --help     show this help message" << std::endl;
  std::cerr << "    -V, --version  bpftrace version" << std::endl;
  std::cerr << std::endl;
  // clang-format on
  return;
}

std::unique_ptr<Output> prepare_output(const std::string& output_file,
                                       const std::string& output_format)
{
  std::ostream* os = &std::cout;
  std::ofstream outputstream;
  if (!output_file.empty())
  {
    outputstream.open(output_file);
    if (outputstream.fail())
    {
      LOG(ERROR) << "Failed to open output file: \"" << output_file
                 << "\": " << strerror(errno);
      return nullptr;
    }
    os = &outputstream;
  }

  std::unique_ptr<Output> output;
  if (output_format.empty() || output_format == "text")
  {
    output = std::make_unique<TextOutput>(*os);
  }
  else if (output_format == "json")
  {
    output = std::make_unique<JsonOutput>(*os);
  }
  else
  {
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
  const char* const short_opts = "f:hVo:v";
  option long_opts[] = {
    option{ "help", no_argument, nullptr, 'h' },
    option{ "version", no_argument, nullptr, 'V' },
    option{ nullptr, 0, nullptr, 0 }, // Must be last
  };

  while ((c = getopt_long(argc, argv, short_opts, long_opts, nullptr)) != -1)
  {
    switch (c)
    {
      case 'o':
        output_file = optarg;
        break;
      case 'f':
        output_format = optarg;
        break;
      case 'h':
        usage();
        return 0;
      case 'V':
        std::cout << "bpftrace " << BPFTRACE_VERSION << std::endl;
        return 0;
      case 'v':
        bt_verbose = true;
        break;
      default:
        usage();
        return 1;
    }
  }

  if (!argv[optind])
  {
    usage();
    return 1;
  }

  auto output = prepare_output(output_file, output_format);
  if (!output)
    return 1;

  BPFtrace bpftrace(std::move(output));
  int err = aot::load(bpftrace, argv[optind]);
  if (err)
  {
    LOG(ERROR) << "Failed to load AOT script";
    return err;
  }

  err = bpftrace.run(std::move(bpftrace.bytecode_));
  if (err)
    return err;

  std::cout << "\n\n";
  return bpftrace.print_maps();

  return 0;
}
