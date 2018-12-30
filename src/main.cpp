#include <iostream>
#include <signal.h>
#include <sys/resource.h>
#include <unistd.h>

#include "bpforc.h"
#include "bpftrace.h"
#include "clang_parser.h"
#include "codegen_llvm.h"
#include "driver.h"
#include "list.h"
#include "printer.h"
#include "semantic_analyser.h"
#include "tracepoint_format_parser.h"

using namespace bpftrace;

void usage()
{
  std::cerr << "USAGE:" << std::endl;
  std::cerr << "    bpftrace [options] filename" << std::endl;
  std::cerr << "    bpftrace [options] -e 'program'" << std::endl << std::endl;
  std::cerr << "OPTIONS:" << std::endl;
  std::cerr << "    -d             debug info dry run" << std::endl;
  std::cerr << "    -dd            verbose debug info dry run" << std::endl;
  std::cerr << "    -e 'program'   execute this program" << std::endl;
  std::cerr << "    -h             show this help message" << std::endl;
  std::cerr << "    -l [search]    list probes" << std::endl;
  std::cerr << "    -p PID         enable USDT probes on PID" << std::endl;
  std::cerr << "    -c 'CMD'       run CMD and enable USDT probes on resulting process" << std::endl;
  std::cerr << "    -v             verbose messages" << std::endl << std::endl;
  std::cerr << "EXAMPLES:" << std::endl;
  std::cerr << "bpftrace -l '*sleep*'" << std::endl;
  std::cerr << "    list probes containing \"sleep\"" << std::endl;
  std::cerr << "bpftrace -e 'kprobe:do_nanosleep { printf(\"PID %d sleeping...\\n\", pid); }'" << std::endl;
  std::cerr << "    trace processes calling sleep" << std::endl;
  std::cerr << "bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'" << std::endl;
  std::cerr << "    count syscalls by process name" << std::endl;
}

static void enforce_infinite_rlimit() {
  struct rlimit rl = {};
  if (getrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
    std::cerr << "Warning: couldn't set RLIMIT for bpftrace. " <<
        "If your program is not loading, you can try " <<
        "\"ulimit -l 8192\" to fix the problem" << std::endl;
    return;
  }
  rl.rlim_max = RLIM_INFINITY;
  rl.rlim_cur = rl.rlim_max;
  if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0)
    std::cerr << "Warning: couldn't set RLIMIT for bpftrace. " <<
        "If your program is not loading, you can try " <<
        "\"ulimit -l 8192\" to fix the problem" << std::endl;
}

bool is_root()
{
  if (geteuid() != 0)
  {
    std::cerr << "ERROR: bpftrace currently only supports running as the root user." << std::endl;
    return false;
  }
  else
    return true;
}

int main(int argc, char *argv[])
{
  int err;
  Driver driver;
  char *pid_str = nullptr;
  char *cmd_str = nullptr;
  bool listing = false;

  std::string script, search;
  int c;
  while ((c = getopt(argc, argv, "de:hlp:vc:")) != -1)
  {
    switch (c)
    {
      case 'd':
        bt_debug++;
        if (bt_debug == DebugLevel::kNone) {
          usage();
          return 1;
        }
        break;
      case 'v':
        bt_verbose = true;
        break;
      case 'e':
        script = optarg;
        break;
      case 'p':
        pid_str = optarg;
        break;
      case 'l':
        listing = true;
        break;
      case 'c':
        cmd_str = optarg;
        break;
      default:
        usage();
        return 1;
    }
  }

  if (argc == 1) {
    usage();
    return 1;
  }

  if (bt_verbose && (bt_debug != DebugLevel::kNone))
  {
    // TODO: allow both
    std::cerr << "USAGE: Use either -v or -d." << std::endl;
    return 1;
  }

  if (cmd_str && pid_str)
  {
    std::cerr << "USAGE: Cannot use both -c and -p." << std::endl;
    usage();
    return 1;
  }

  // Listing probes
  if (listing)
  {
    if (!is_root())
      return 1;

    if (optind == argc-1)
      list_probes(argv[optind]);
    else if (optind == argc)
      list_probes();
    else
    {
      usage();
    }
    return 0;
  }

  if (script.empty())
  {
    // Script file
    char *file_name = argv[optind];
    err = driver.parse_file(file_name);
    optind++;
  }
  else
  {
    // Script is provided as a command line argument
    err = driver.parse_str(script);
  }

  if (!is_root())
    return 1;

  if (err)
    return err;

  // FIXME (mmarchini): maybe we don't want to always enforce an infinite
  // rlimit?
  enforce_infinite_rlimit();

  BPFtrace bpftrace;

  // positional parameters
  while (optind < argc) {
    bpftrace.add_param(argv[optind]);
    optind++;
  }

  // defaults
  bpftrace.join_argnum_ = 16;
  bpftrace.join_argsize_ = 1024;

  // PID is currently only used for USDT probes that need enabling. Future work:
  // - make PID a filter for all probe types: pass to perf_event_open(), etc.
  // - provide PID in USDT probe specification as a way to override -p.
  if (pid_str)
    bpftrace.pid_ = atoi(pid_str);

  if (cmd_str)
    bpftrace.cmd_ = cmd_str;

  TracepointFormatParser::parse(driver.root_);

  if (bt_debug != DebugLevel::kNone)
  {
    ast::Printer p(std::cout);
    driver.root_->accept(p);
    std::cout << std::endl;
  }

  ClangParser clang;
  clang.parse(driver.root_, bpftrace.structs_);

  ast::SemanticAnalyser semantics(driver.root_, bpftrace);
  err = semantics.analyse();
  if (err)
    return err;

  err = semantics.create_maps(bt_debug != DebugLevel::kNone);
  if (err)
    return err;

  ast::CodegenLLVM llvm(driver.root_, bpftrace);
  auto bpforc = llvm.compile(bt_debug);

  if (bt_debug != DebugLevel::kNone)
    return 0;

  // Empty signal handler for cleanly terminating the program
  struct sigaction act = {};
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
