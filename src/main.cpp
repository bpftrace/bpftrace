#include <iostream>
#include <signal.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <string.h>

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
  std::cerr << "    -B MODE        output buffering mode ('line', 'full', or 'none')" << std::endl;
  std::cerr << "    -d             debug info dry run" << std::endl;
  std::cerr << "    -dd            verbose debug info dry run" << std::endl;
  std::cerr << "    -e 'program'   execute this program" << std::endl;
  std::cerr << "    -h             show this help message" << std::endl;
  std::cerr << "    -l [search]    list probes" << std::endl;
  std::cerr << "    -p PID         enable USDT probes on PID" << std::endl;
  std::cerr << "    -c 'CMD'       run CMD and enable USDT probes on resulting process" << std::endl;
  std::cerr << "    -v             verbose messages" << std::endl;
  std::cerr << "    --version      bpftrace version" << std::endl << std::endl;
  std::cerr << "ENVIRONMENT:" << std::endl;
  std::cerr << "    BPFTRACE_STRLEN           [default: 64] bytes on BPF stack per str()" << std::endl;
  std::cerr << "    BPFTRACE_NO_CPP_DEMANGLE  [default: 0] disable C++ symbol demangling" << std::endl << std::endl;
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
  int err;

  rl.rlim_max = RLIM_INFINITY;
  rl.rlim_cur = rl.rlim_max;
  err = setrlimit(RLIMIT_MEMLOCK, &rl);
  if (err)
    std::cerr << std::strerror(err)<<": couldn't set RLIMIT for bpftrace. " <<
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

bool is_numeric(char* string)
{
  while(char current_char = *string++)
  {
    if (!isdigit(current_char))
      return false;
  }
  return true;
}

int main(int argc, char *argv[])
{
  int err;
  char *pid_str = nullptr;
  char *cmd_str = nullptr;
  bool listing = false;

  if (argc > 1 && strcmp(argv[1], "--version") == 0)
  {
    std::cout << "bpftrace " << BPFTRACE_VERSION<< "\n" << std::endl;
    return 0;
  }

  std::string script, search, file_name;
  int c;
  while ((c = getopt(argc, argv, "dB:e:hlp:vc:")) != -1)
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
      case 'B':
        if (std::strcmp(optarg, "line") == 0) {
          std::setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
        } else if (std::strcmp(optarg, "full") == 0) {
          std::setvbuf(stdout, NULL, _IOFBF, BUFSIZ);
        } else if (std::strcmp(optarg, "none") == 0) {
          std::setvbuf(stdout, NULL, _IONBF, BUFSIZ);
        } else {
          std::cerr << "USAGE: -B must be either 'line', 'full', or 'none'." << std::endl;
          return 1;
        }
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
      case 'h':
        usage();
        return 0;
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

  BPFtrace bpftrace;
  Driver driver(bpftrace);

  // PID is currently only used for USDT probes that need enabling. Future work:
  // - make PID a filter for all probe types: pass to perf_event_open(), etc.
  // - provide PID in USDT probe specification as a way to override -p.
  bpftrace.pid_ = 0;
  if (pid_str)
  {
    if (!is_numeric(pid_str))
    {
      std::cerr << "ERROR: pid '" << pid_str << "' is not a valid number." << std::endl;
      return 1;
    }
    bpftrace.pid_ = strtol(pid_str, NULL, 10);
  }

  // Listing probes
  if (listing)
  {
    if (!is_root())
      return 1;

    if (optind == argc-1)
      list_probes(argv[optind], bpftrace.pid_);
    else if (optind == argc)
      list_probes("", bpftrace.pid_);
    else
    {
      usage();
    }
    return 0;
  }

  if (script.empty())
  {
    // Script file
    if (argv[optind] == nullptr)
    {
      std::cerr << "USAGE: filename or -e 'program' required." << std::endl;
      return 1;
    }
    file_name = std::string(argv[optind]);
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

  // positional parameters
  while (optind < argc) {
    bpftrace.add_param(argv[optind]);
    optind++;
  }

  // defaults
  bpftrace.join_argnum_ = 16;
  bpftrace.join_argsize_ = 1024;

  if(const char* env_p = std::getenv("BPFTRACE_STRLEN")) {
    uint64_t proposed;
    std::istringstream stringstream(env_p);
    if (!(stringstream >> proposed)) {
      std::cerr << "Env var 'BPFTRACE_STRLEN' did not contain a valid uint64_t, or was zero-valued." << std::endl;
      return 1;
    }

    // in practice, the largest buffer I've seen fit into the BPF stack was 240 bytes.
    // I've set the bar lower, in case your program has a deeper stack than the one from my tests,
    // in the hope that you'll get this instructive error instead of getting the BPF verifier's error.
    if (proposed > 200) {
      // the verifier errors you would encounter when attempting larger allocations would be:
      // >240=  <Looks like the BPF stack limit of 512 bytes is exceeded. Please move large on stack variables into BPF per-cpu array map.>
      // ~1024= <A call to built-in function 'memset' is not supported.>
      std::cerr << "'BPFTRACE_STRLEN' " << proposed << " exceeds the current maximum of 200 bytes." << std::endl
      << "This limitation is because strings are currently stored on the 512 byte BPF stack." << std::endl
      << "Long strings will be pursued in: https://github.com/iovisor/bpftrace/issues/305" << std::endl;
      return 1;
    }
    bpftrace.strlen_ = proposed;
  }

  if (const char* env_p = std::getenv("BPFTRACE_NO_CPP_DEMANGLE"))
  {
    if (std::string(env_p) == "1")
      bpftrace.demangle_cpp_symbols = false;
    else if (std::string(env_p) == "0")
      bpftrace.demangle_cpp_symbols = true;
    else
    {
      std::cerr << "Env var 'BPFTRACE_NO_CPP_DEMANGLE' did not contain a valid value (0 or 1)." << std::endl;
      return 1;
    }
  }

  if (cmd_str)
    bpftrace.cmd_ = cmd_str;

  if (TracepointFormatParser::parse(driver.root_) == false)
    return 1;

  if (bt_debug != DebugLevel::kNone)
  {
    ast::Printer p(std::cout);
    driver.root_->accept(p);
    std::cout << std::endl;
  }

  ClangParser clang;
  std::vector<std::string> extra_flags;
  {
    struct utsname utsname;
    uname(&utsname);
    std::string ksrc, kobj;
    auto kdirs = get_kernel_dirs(utsname);
    ksrc = std::get<0>(kdirs);
    kobj = std::get<1>(kdirs);

    if (ksrc != "")
      extra_flags = get_kernel_cflags(utsname.machine, ksrc, kobj);
  }
  clang.parse(driver.root_, bpftrace, extra_flags);

  if (script.empty())
  {
    err = driver.parse_file(file_name);
  }
  else
  {
    err = driver.parse_str(script);
  }

  if (err)
    return err;

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
