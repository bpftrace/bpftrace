#include <iostream>
#include <signal.h>

#include "bpforc.h"
#include "bpftrace.h"
#include "codegen_llvm.h"
#include "driver.h"
#include "printer.h"
#include "semantic_analyser.h"

using namespace bpftrace;

void usage()
{
  std::cerr << "USAGE:" << std::endl;
  std::cerr << "    bpftrace [options] filename" << std::endl;
  std::cerr << "    bpftrace [options] -e 'program'" << std::endl << std::endl;
  std::cerr << "OPTIONS:" << std::endl;
  std::cerr << "    -e 'program'   execute this program" << std::endl;
  std::cerr << "    -v    verbose messages" << std::endl;
  std::cerr << "    -d    debug info dry run" << std::endl << std::endl;
  std::cerr << "EXAMPLES:" << std::endl;
  std::cerr << "bpftrace -e 'kprobe:sys_nanosleep { printf(\"PID %d sleeping...\\n\", pid); }'" << std::endl;
  std::cerr << "    trace processes calling sleep" << std::endl;
  std::cerr << "bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'" << std::endl;
  std::cerr << "    count syscalls by process name" << std::endl;
}

int main(int argc, char *argv[])
{
  int err;
  Driver driver;

  std::string script;
  int c;
  while ((c = getopt(argc, argv, "de:v")) != -1)
  {
    switch (c)
    {
      case 'd':
        bt_debug = true;
        break;
      case 'v':
        bt_verbose = true;
        break;
      case 'e':
        script = optarg;
        break;
      default:
        usage();
        return 1;
    }
  }

  if (bt_verbose && bt_debug)
  {
    // TODO: allow both
    std::cerr << "USAGE: Use either -v or -d." << std::endl;
    return 1;
  }

  if (script.empty())
  {
    // There should only be 1 non-option argument (the script file)
    if (optind != argc-1)
    {
      usage();
      return 1;
    }
    char *file_name = argv[optind];
    err = driver.parse_file(file_name);
  }
  else
  {
    // Script is provided as a command line argument
    if (optind != argc)
    {
      usage();
      return 1;
    }
    err = driver.parse_str(script);
  }

  if (err)
    return err;

  BPFtrace bpftrace;

  if (bt_debug)
  {
    ast::Printer p(std::cout);
    driver.root_->accept(p);
    std::cout << std::endl;
  }

  ast::SemanticAnalyser semantics(driver.root_, bpftrace);
  err = semantics.analyse();
  if (err)
    return err;

  err = semantics.create_maps(bt_debug);
  if (err)
    return err;

  ast::CodegenLLVM llvm(driver.root_, bpftrace);
  auto bpforc = llvm.compile(bt_debug);

  if (bt_debug)
    return 0;

  // Empty signal handler for cleanly terminating the program
  struct sigaction act;
  act.sa_handler = [](int) { };
  sigaction(SIGINT, &act, NULL);

  int num_probes = bpftrace.num_probes();
  if (num_probes == 0)
  {
    std::cout << "No probes to attach" << std::endl;
    return 1;
  }
  else if (num_probes == 1)
    std::cout << "Attaching " << bpftrace.num_probes() << " probe..." << std::endl;
  else
    std::cout << "Attaching " << bpftrace.num_probes() << " probes..." << std::endl;

  err = bpftrace.run(move(bpforc));
  if (err)
    return err;

  std::cout << "\n\n";

  err = bpftrace.print_maps();
  if (err)
    return err;

  return 0;
}
