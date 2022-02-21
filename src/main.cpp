#include <array>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <limits>
#include <optional>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "aot/aot.h"
#include "ast/bpforc/bpforc.h"
#include "ast/pass_manager.h"

#include "ast/passes/codegen_llvm.h"
#include "ast/passes/field_analyser.h"
#include "ast/passes/node_counter.h"
#include "ast/passes/portability_analyser.h"
#include "ast/passes/resource_analyser.h"
#include "ast/passes/semantic_analyser.h"

#include "bpffeature.h"
#include "bpftrace.h"
#include "build_info.h"
#include "child.h"
#include "clang_parser.h"
#include "driver.h"
#include "lockdown.h"
#include "log.h"
#include "output.h"
#include "probe_matcher.h"
#include "procmon.h"
#include "tracepoint_format_parser.h"

using namespace bpftrace;

namespace {
enum class OutputBufferConfig {
  UNSET = 0,
  LINE,
  FULL,
  NONE,
};

enum class TestMode
{
  UNSET = 0,
  SEMANTIC,
  CODEGEN,
};

enum class BuildMode
{
  // Compile script and run immediately
  DYNAMIC = 0,
  // Compile script into portable executable
  AHEAD_OF_TIME,
};

enum Options
{
  INFO = 2000,
  EMIT_ELF,
  NO_WARNING,
  TEST,
  AOT,
  HELP,
  VERSION,
  USDT_SEMAPHORE,
  UNSAFE,
  BTF,
  INCLUDE,
};
} // namespace

void usage()
{
  // clang-format off
  std::cerr << "USAGE:" << std::endl;
  std::cerr << "    bpftrace [options] filename" << std::endl;
  std::cerr << "    bpftrace [options] - <stdin input>" << std::endl;
  std::cerr << "    bpftrace [options] -e 'program'" << std::endl;
  std::cerr << std::endl;
  std::cerr << "OPTIONS:" << std::endl;
  std::cerr << "    -B MODE        output buffering mode ('full', 'none')" << std::endl;
  std::cerr << "    -f FORMAT      output format ('text', 'json')" << std::endl;
  std::cerr << "    -o file        redirect bpftrace output to file" << std::endl;
  std::cerr << "    -d             debug info dry run" << std::endl;
  std::cerr << "    -dd            verbose debug info dry run" << std::endl;
  std::cerr << "    -e 'program'   execute this program" << std::endl;
  std::cerr << "    -h, --help     show this help message" << std::endl;
  std::cerr << "    -I DIR         add the directory to the include search path" << std::endl;
  std::cerr << "    --include FILE add an #include file before preprocessing" << std::endl;
  std::cerr << "    -l [search]    list probes" << std::endl;
  std::cerr << "    -p PID         enable USDT probes on PID" << std::endl;
  std::cerr << "    -c 'CMD'       run CMD and enable USDT probes on resulting process" << std::endl;
  std::cerr << "    --usdt-file-activation" << std::endl;
  std::cerr << "                   activate usdt semaphores based on file path" << std::endl;
  std::cerr << "    --unsafe       allow unsafe builtin functions" << std::endl;
  std::cerr << "    -q             keep messages quiet" << std::endl;
  std::cerr << "    -v             verbose messages" << std::endl;
  std::cerr << "    --info         Print information about kernel BPF support" << std::endl;
  std::cerr << "    -k             emit a warning when a bpf helper returns an error (except read functions)" << std::endl;
  std::cerr << "    -kk            check all bpf helper functions" << std::endl;
  std::cerr << "    -V, --version  bpftrace version" << std::endl;
  std::cerr << "    --no-warnings  disable all warning messages" << std::endl;
  std::cerr << std::endl;
  std::cerr << "ENVIRONMENT:" << std::endl;
  std::cerr << "    BPFTRACE_STRLEN             [default: 64] bytes on BPF stack per str()" << std::endl;
  std::cerr << "    BPFTRACE_NO_CPP_DEMANGLE    [default: 0] disable C++ symbol demangling" << std::endl;
  std::cerr << "    BPFTRACE_MAP_KEYS_MAX       [default: 4096] max keys in a map" << std::endl;
  std::cerr << "    BPFTRACE_CAT_BYTES_MAX      [default: 10k] maximum bytes read by cat builtin" << std::endl;
  std::cerr << "    BPFTRACE_MAX_PROBES         [default: 512] max number of probes" << std::endl;
  std::cerr << "    BPFTRACE_MAX_BPF_PROGS      [default: 512] max number of generated BPF programs" << std::endl;
  std::cerr << "    BPFTRACE_LOG_SIZE           [default: 1000000] log size in bytes" << std::endl;
  std::cerr << "    BPFTRACE_PERF_RB_PAGES      [default: 64] pages per CPU to allocate for ring buffer" << std::endl;
  std::cerr << "    BPFTRACE_NO_USER_SYMBOLS    [default: 0] disable user symbol resolution" << std::endl;
  std::cerr << "    BPFTRACE_CACHE_USER_SYMBOLS [default: auto] enable user symbol cache" << std::endl;
  std::cerr << "    BPFTRACE_VMLINUX            [default: none] vmlinux path used for kernel symbol resolution" << std::endl;
  std::cerr << "    BPFTRACE_BTF                [default: none] BTF file" << std::endl;
  std::cerr << std::endl;
  std::cerr << "EXAMPLES:" << std::endl;
  std::cerr << "bpftrace -l '*sleep*'" << std::endl;
  std::cerr << "    list probes containing \"sleep\"" << std::endl;
  std::cerr << "bpftrace -e 'kprobe:do_nanosleep { printf(\"PID %d sleeping...\\n\", pid); }'" << std::endl;
  std::cerr << "    trace processes calling sleep" << std::endl;
  std::cerr << "bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'" << std::endl;
  std::cerr << "    count syscalls by process name" << std::endl;
  // clang-format on
}

static void enforce_infinite_rlimit() {
  struct rlimit rl = {};
  int err;

  rl.rlim_max = RLIM_INFINITY;
  rl.rlim_cur = rl.rlim_max;
  err = setrlimit(RLIMIT_MEMLOCK, &rl);
  if (err)
    LOG(ERROR) << std::strerror(err) << ": couldn't set RLIMIT_MEMLOCK for "
               << "bpftrace. If your program is not loading, you can try "
               << "\"ulimit -l 8192\" to fix the problem";
}

bool is_root()
{
  if (geteuid() != 0)
  {
    LOG(ERROR) << "bpftrace currently only supports running as the root user.";
    return false;
  }
  else
    return true;
}

static void info()
{
  struct utsname utsname;
  uname(&utsname);

  std::cerr << "System" << std::endl
            << "  OS: " << utsname.sysname << " " << utsname.release << " "
            << utsname.version << std::endl
            << "  Arch: " << utsname.machine << std::endl;

  std::cerr << std::endl;
  std::cerr << BuildInfo::report();

  std::cerr << std::endl;
  std::cerr << BPFfeature().report();
}

static std::optional<struct timespec> get_boottime()
{
  std::optional<struct timespec> ret = std::nullopt;
  long lowest_delta = std::numeric_limits<long>::max();

  // Run the "triple vdso sandwich" 5 times, taking the result from the
  // iteration with the lowest delta between first and last clock_gettime()
  // calls.
  for (int i = 0; i < 5; ++i)
  {
    struct timespec before, after, boottime;
    long delta;

    if (::clock_gettime(CLOCK_REALTIME, &before))
      continue;

    if (::clock_gettime(CLOCK_BOOTTIME, &boottime))
      continue;

    if (::clock_gettime(CLOCK_REALTIME, &after))
      continue;

    // There's no way 3 VDSO calls should take more than 1s. We'll
    // also ignore the case where we cross a 1s boundary b/c that
    // can only happen once and we're running this loop 5 times.
    // This helps keep the math simple.
    if (before.tv_sec != after.tv_sec)
      continue;

    delta = after.tv_nsec - before.tv_nsec;

    // Time went backwards
    if (delta < 0)
      continue;

    // Lowest delta seen so far, compute boot realtime and store it
    if (delta < lowest_delta)
    {
      struct timespec boottime_realtime;
      long nsec_avg = (before.tv_nsec + after.tv_nsec) / 2;
      if (nsec_avg - boottime.tv_nsec < 0)
      {
        boottime_realtime.tv_sec = after.tv_sec - boottime.tv_sec - 1;
        boottime_realtime.tv_nsec = nsec_avg - boottime.tv_nsec + 1e9;
      }
      else
      {
        boottime_realtime.tv_sec = after.tv_sec - boottime.tv_sec;
        boottime_realtime.tv_nsec = nsec_avg - boottime.tv_nsec;
      }

      lowest_delta = delta;
      ret = boottime_realtime;
    }
  }

  if (ret && lowest_delta >= 1e5)
    LOG(WARNING) << (lowest_delta / 1e3)
                 << "us skew detected when calculating boot time. strftime() "
                    "builtin may be inaccurate";

  return ret;
}

[[nodiscard]] static bool parse_env(BPFtrace& bpftrace)
{
  if (!get_uint64_env_var("BPFTRACE_STRLEN", bpftrace.strlen_))
    return false;

  // in practice, the largest buffer I've seen fit into the BPF stack was 240
  // bytes. I've set the bar lower, in case your program has a deeper stack than
  // the one from my tests, in the hope that you'll get this instructive error
  // instead of getting the BPF verifier's error.
  if (bpftrace.strlen_ > 200)
  {
    // the verifier errors you would encounter when attempting larger
    // allocations would be: >240=  <Looks like the BPF stack limit of 512 bytes
    // is exceeded. Please move large on stack variables into BPF per-cpu array
    // map.> ~1024= <A call to built-in function 'memset' is not supported.>
    LOG(ERROR) << "'BPFTRACE_STRLEN' " << bpftrace.strlen_
               << " exceeds the current maximum of 200 bytes.\n"
               << "This limitation is because strings are currently stored on "
                  "the 512 byte BPF stack.\n"
               << "Long strings will be pursued in: "
                  "https://github.com/iovisor/bpftrace/issues/305";
    return false;
  }

  if (const char* env_p = std::getenv("BPFTRACE_NO_CPP_DEMANGLE"))
  {
    if (std::string(env_p) == "1")
      bpftrace.demangle_cpp_symbols_ = false;
    else if (std::string(env_p) == "0")
      bpftrace.demangle_cpp_symbols_ = true;
    else
    {
      LOG(ERROR) << "Env var 'BPFTRACE_NO_CPP_DEMANGLE' did not contain a "
                    "valid value (0 or 1).";
      return false;
    }
  }

  if (!get_uint64_env_var("BPFTRACE_MAP_KEYS_MAX", bpftrace.mapmax_))
    return false;

  if (!get_uint64_env_var("BPFTRACE_MAX_PROBES", bpftrace.max_probes_))
    return false;

  if (!get_uint64_env_var("BPFTRACE_MAX_BPF_PROGS", bpftrace.max_programs_))
    return false;

  if (!get_uint64_env_var("BPFTRACE_LOG_SIZE", bpftrace.log_size_))
    return false;

  if (!get_uint64_env_var("BPFTRACE_PERF_RB_PAGES", bpftrace.perf_rb_pages_))
    return false;

  if (!get_uint64_env_var("BPFTRACE_MAX_TYPE_RES_ITERATIONS",
                          bpftrace.max_type_res_iterations))
    return 1;

  if (!get_uint64_env_var("BPFTRACE_MAX_TYPE_RES_ITERATIONS",
                          bpftrace.max_type_res_iterations))
    return false;

  if (const char* env_p = std::getenv("BPFTRACE_CAT_BYTES_MAX"))
  {
    uint64_t proposed;
    std::istringstream stringstream(env_p);
    if (!(stringstream >> proposed))
    {
      LOG(ERROR) << "Env var 'BPFTRACE_CAT_BYTES_MAX' did not contain a valid "
                    "uint64_t, or was zero-valued.";
      return false;
    }
    bpftrace.cat_bytes_max_ = proposed;
  }

  if (const char* env_p = std::getenv("BPFTRACE_NO_USER_SYMBOLS"))
  {
    std::string s(env_p);
    if (s == "1")
      bpftrace.resolve_user_symbols_ = false;
    else if (s == "0")
      bpftrace.resolve_user_symbols_ = true;
    else
    {
      LOG(ERROR) << "Env var 'BPFTRACE_NO_USER_SYMBOLS' did not contain a "
                    "valid value (0 or 1).";
      return false;
    }
  }

  if (const char* env_p = std::getenv("BPFTRACE_CACHE_USER_SYMBOLS"))
  {
    std::string s(env_p);
    if (s == "1")
      bpftrace.cache_user_symbols_ = true;
    else if (s == "0")
      bpftrace.cache_user_symbols_ = false;
    else
    {
      LOG(ERROR) << "Env var 'BPFTRACE_CACHE_USER_SYMBOLS' did not contain a "
                    "valid value (0 or 1).";
      return false;
    }
  }
  else
  {
    // enable user symbol cache if ASLR is disabled on system or `-c` option is
    // given
    bpftrace.cache_user_symbols_ = !bpftrace.cmd_.empty() ||
                                   !bpftrace.is_aslr_enabled(-1);
  }

  uint64_t node_max = std::numeric_limits<uint64_t>::max();
  if (!get_uint64_env_var("BPFTRACE_NODE_MAX", node_max))
    return false;

  bpftrace.ast_max_nodes_ = node_max;
  return true;
}

[[nodiscard]] std::unique_ptr<ast::Node> parse(
    BPFtrace& bpftrace,
    const std::string& name,
    const std::string& program,
    const std::vector<std::string>& include_dirs,
    const std::vector<std::string>& include_files)
{
  Driver driver(bpftrace);
  driver.source(name, program);
  int err;

  err = driver.parse();
  if (err)
    return nullptr;

  ast::FieldAnalyser fields(driver.root.get(), bpftrace);
  err = fields.analyse();
  if (err)
    return nullptr;

  if (TracepointFormatParser::parse(driver.root.get(), bpftrace) == false)
    return nullptr;

  ClangParser clang;
  std::vector<std::string> extra_flags;
  {
    struct utsname utsname;
    uname(&utsname);
    std::string ksrc, kobj;
    auto kdirs = get_kernel_dirs(utsname, !bpftrace.feature_->has_btf());
    ksrc = std::get<0>(kdirs);
    kobj = std::get<1>(kdirs);

    if (ksrc != "")
      extra_flags = get_kernel_cflags(utsname.machine, ksrc, kobj);
  }
  extra_flags.push_back("-include");
  extra_flags.push_back(CLANG_WORKAROUNDS_H);

  for (auto dir : include_dirs)
  {
    extra_flags.push_back("-I");
    extra_flags.push_back(dir);
  }
  for (auto file : include_files)
  {
    extra_flags.push_back("-include");
    extra_flags.push_back(file);
  }

  // NOTE(mmarchini): if there are no C definitions, clang parser won't run to
  // avoid issues in some versions. Since we're including files in the command
  // line, we want to force parsing, so we make sure C definitions are not
  // empty before going to clang parser stage.
  if (!include_files.empty() && driver.root->c_definitions.empty())
    driver.root->c_definitions = "#define __BPFTRACE_DUMMY__";

  if (!clang.parse(driver.root.get(), bpftrace, extra_flags))
    return nullptr;

  err = driver.parse();
  if (err)
    return nullptr;

  return std::move(driver.root);
}

ast::PassManager CreateDynamicPM()
{
  ast::PassManager pm;
  pm.AddPass(ast::CreateSemanticPass());
  pm.AddPass(ast::CreateCounterPass());
  pm.AddPass(ast::CreateResourcePass());

  return pm;
}

ast::PassManager CreateAotPM(std::string __attribute__((unused)))
{
  ast::PassManager pm;
  pm.AddPass(ast::CreateSemanticPass());
  pm.AddPass(ast::CreatePortabilityPass());
  pm.AddPass(ast::CreateResourcePass());

  return pm;
}

struct Args
{
  std::string pid_str;
  std::string cmd_str;
  bool listing = false;
  bool safe_mode = true;
  bool usdt_file_activation = false;
  int helper_check_level = 0;
  TestMode test_mode = TestMode::UNSET;
  std::string script;
  std::string search;
  std::string filename;
  std::string output_file;
  std::string output_format;
  std::string output_elf;
  std::string aot;
  OutputBufferConfig obc = OutputBufferConfig::UNSET;
  BuildMode build_mode = BuildMode::DYNAMIC;
  std::vector<std::string> include_dirs;
  std::vector<std::string> include_files;
  std::vector<std::string> params;
};

Args parse_args(int argc, char* argv[])
{
  Args args;

  const char* const short_options = "dbB:f:e:hlp:vqc:Vo:I:k";
  option long_options[] = {
    option{ "help", no_argument, nullptr, Options::HELP },
    option{ "version", no_argument, nullptr, Options::VERSION },
    option{
        "usdt-file-activation", no_argument, nullptr, Options::USDT_SEMAPHORE },
    option{ "unsafe", no_argument, nullptr, Options::UNSAFE },
    option{ "btf", no_argument, nullptr, Options::BTF },
    option{ "include", required_argument, nullptr, Options::INCLUDE },
    option{ "info", no_argument, nullptr, Options::INFO },
    option{ "emit-elf", required_argument, nullptr, Options::EMIT_ELF },
    option{ "no-warnings", no_argument, nullptr, Options::NO_WARNING },
    option{ "test", required_argument, nullptr, Options::TEST },
    option{ "aot", required_argument, nullptr, Options::AOT },
    option{ nullptr, 0, nullptr, 0 }, // Must be last
  };

  int c;
  while ((c = getopt_long(
              argc, argv, short_options, long_options, nullptr)) != -1)
  {
    switch (c)
    {
      case Options::INFO: // --info
        if (is_root())
        {
          info();
          exit(0);
        }
        exit(1);
        break;
      case Options::EMIT_ELF: // --emit-elf
        args.output_elf = optarg;
        break;
      case Options::NO_WARNING: // --no-warnings
        DISABLE_LOG(WARNING);
        break;
      case Options::TEST: // --test
        if (std::strcmp(optarg, "semantic") == 0)
          args.test_mode = TestMode::SEMANTIC;
        else if (std::strcmp(optarg, "codegen") == 0)
          args.test_mode = TestMode::CODEGEN;
        else
        {
          LOG(ERROR) << "USAGE: --test must be either 'semantic' or 'codegen'.";
          exit(1);
        }
        break;
      case Options::AOT: // --aot
        args.aot = optarg;
        args.build_mode = BuildMode::AHEAD_OF_TIME;
        break;
      case 'o':
        args.output_file = optarg;
        break;
      case 'd':
        bt_debug++;
        if (bt_debug == DebugLevel::kNone) {
          usage();
          exit(1);
        }
        break;
      case 'q':
        bt_quiet = true;
        break;
      case 'v':
        bt_verbose = true;
        break;
      case 'B':
        if (std::strcmp(optarg, "line") == 0) {
          args.obc = OutputBufferConfig::LINE;
        } else if (std::strcmp(optarg, "full") == 0) {
          args.obc = OutputBufferConfig::FULL;
        } else if (std::strcmp(optarg, "none") == 0) {
          args.obc = OutputBufferConfig::NONE;
        } else {
          LOG(ERROR) << "USAGE: -B must be either 'line', 'full', or 'none'.";
          exit(1);
        }
        break;
      case 'f':
        args.output_format = optarg;
        break;
      case 'e':
        args.script = optarg;
        break;
      case 'p':
        args.pid_str = optarg;
        break;
      case 'I':
        args.include_dirs.push_back(optarg);
        break;
      case Options::INCLUDE:
        args.include_files.push_back(optarg);
        break;
      case 'l':
        args.listing = true;
        break;
      case 'c':
        args.cmd_str = optarg;
        break;
      case Options::USDT_SEMAPHORE:
        args.usdt_file_activation = true;
        break;
      case Options::UNSAFE:
        args.safe_mode = false;
        break;
      case 'b':
      case Options::BTF:
        break;
      case 'h':
      case Options::HELP:
        usage();
        exit(0);
      case 'V':
      case Options::VERSION:
        std::cout << "bpftrace " << BPFTRACE_VERSION << std::endl;
        exit(0);
      case 'k':
        args.helper_check_level++;
        if (args.helper_check_level >= 3)
        {
          usage();
          exit(1);
        }
        break;
      default:
        usage();
        exit(1);
    }
  }

  if (argc == 1) {
    usage();
    exit(1);
  }

  if (bt_verbose && (bt_debug != DebugLevel::kNone))
  {
    // TODO: allow both
    LOG(ERROR) << "USAGE: Use either -v or -d.";
    exit(1);
  }

  if (!args.cmd_str.empty() && !args.pid_str.empty())
  {
    LOG(ERROR) << "USAGE: Cannot use both -c and -p.";
    usage();
    exit(1);
  }

  // Difficult to serialize flex generated types
  if (args.helper_check_level && args.build_mode == BuildMode::AHEAD_OF_TIME)
  {
    LOG(ERROR) << "Cannot use -k[k] with --aot";
    exit(1);
  }

  if (args.listing)
  {
    // Expect zero or one positional arguments
    if (optind == argc)
    {
      args.search = "*:*";
    }
    else if (optind == argc - 1)
    {
      args.search = argv[optind];
      if (args.search == "*")
      {
        args.search = "*:*";
      }
      optind++;
    }
    else
    {
      usage();
      exit(1);
    }
  }
  else
  {
    // Expect to find a script either through -e or filename
    if (args.script.empty() && argv[optind] == nullptr)
    {
      LOG(ERROR) << "USAGE: filename or -e 'program' required.";
      exit(1);
    }

    // If no script was specified with -e, then we expect to find a script file
    if (args.script.empty())
    {
      args.filename = argv[optind];
      optind++;
    }

    // Load positional parameters before driver runs so positional
    // parameters used inside attach point definitions can be resolved.
    while (optind < argc)
    {
      args.params.push_back(argv[optind]);
      optind++;
    }
  }

  return args;
}

int main(int argc, char* argv[])
{
  int err;

  const Args args = parse_args(argc, argv);

  std::ostream * os = &std::cout;
  std::ofstream outputstream;
  if (!args.output_file.empty())
  {
    outputstream.open(args.output_file);
    if (outputstream.fail()) {
      LOG(ERROR) << "Failed to open output file: \"" << args.output_file
                 << "\": " << strerror(errno);
      return 1;
    }
    os = &outputstream;
  }

  std::unique_ptr<Output> output;
  if (args.output_format.empty() || args.output_format == "text")
  {
    output = std::make_unique<TextOutput>(*os);
  }
  else if (args.output_format == "json")
  {
    output = std::make_unique<JsonOutput>(*os);
  }
  else {
    LOG(ERROR) << "Invalid output format \"" << args.output_format << "\"\n"
               << "Valid formats: 'text', 'json'";
    return 1;
  }

  switch (args.obc)
  {
    case OutputBufferConfig::UNSET:
    case OutputBufferConfig::LINE:
      std::setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
      break;
    case OutputBufferConfig::FULL:
      std::setvbuf(stdout, NULL, _IOFBF, BUFSIZ);
      break;
    case OutputBufferConfig::NONE:
      std::setvbuf(stdout, NULL, _IONBF, BUFSIZ);
      break;
  }

  BPFtrace bpftrace(std::move(output));

  if (!args.cmd_str.empty())
    bpftrace.cmd_ = args.cmd_str;

  if (!parse_env(bpftrace))
    return 1;

  bpftrace.usdt_file_activation_ = args.usdt_file_activation;
  bpftrace.safe_mode_ = args.safe_mode;
  bpftrace.helper_check_level_ = args.helper_check_level;
  bpftrace.boottime_ = get_boottime();

  if (!args.pid_str.empty())
  {
    try
    {
      bpftrace.procmon_ = std::make_unique<ProcMon>(args.pid_str);
    }
    catch (const std::exception& e)
    {
      LOG(ERROR) << e.what();
      return 1;
    }
  }

  if (!args.cmd_str.empty())
  {
    bpftrace.cmd_ = args.cmd_str;
    try
    {
      bpftrace.child_ = std::make_unique<ChildProc>(args.cmd_str);
    }
    catch (const std::runtime_error& e)
    {
      LOG(ERROR) << "Failed to fork child: " << e.what();
      return -1;
    }
  }

  // Listing probes
  if (args.listing)
  {
    if (!is_root())
      return 1;

    if (args.search.find(':') == std::string::npos &&
        (args.search.find("struct") == 0 || args.search.find("union") == 0 ||
         args.search.find("enum") == 0))
    {
      // Print structure definitions
      bpftrace.probe_matcher_->list_structs(args.search);
      return 0;
    }

    Driver driver(bpftrace);
    driver.listing_ = true;
    driver.source("stdin", args.search);

    int err = driver.parse();
    if (err)
      return err;

    ast::SemanticAnalyser semantics(driver.root.get(), bpftrace, false, true);
    err = semantics.analyse();
    if (err)
      return err;

    bpftrace.probe_matcher_->list_probes(driver.root.get());
    return 0;
  }

  std::string filename;
  std::string program;

  if (!args.filename.empty())
  {
    std::stringstream buf;

    if (args.filename == "-")
    {
      std::string line;
      while (std::getline(std::cin, line))
      {
        // Note we may add an extra newline if the input doesn't end in a new
        // line. This should not matter because bpftrace (the language) is not
        // whitespace sensitive.
        buf << line << std::endl;
      }

      filename = "stdin";
      program = buf.str();
    }
    else
    {
      std::ifstream file(args.filename);
      if (file.fail())
      {
        LOG(ERROR) << "failed to open file '" << args.filename
                   << "': " << std::strerror(errno);
        return -1;
      }

      filename = args.filename;
      program = buf.str();
      buf << file.rdbuf();
      program = buf.str();
    }
  }
  else
  {
    // Script is provided as a command line argument
    filename = "stdin";
    program = args.script;
  }

  for (const auto& param : args.params)
  {
    bpftrace.add_param(param);
  }

  if (!is_root())
    return 1;

  auto lockdown_state = lockdown::detect(bpftrace.feature_);
  if (lockdown_state == lockdown::LockdownState::Confidentiality)
  {
    lockdown::emit_warning(std::cerr);
    return 1;
  }

  // FIXME (mmarchini): maybe we don't want to always enforce an infinite
  // rlimit?
  enforce_infinite_rlimit();

  auto ast_root = parse(
      bpftrace, filename, program, args.include_dirs, args.include_files);
  if (!ast_root)
    return 1;

  ast::PassContext ctx(bpftrace);
  ast::PassManager pm;
  switch (args.build_mode)
  {
    case BuildMode::DYNAMIC:
      pm = CreateDynamicPM();
      break;
    case BuildMode::AHEAD_OF_TIME:
      pm = CreateAotPM(args.aot);
      break;
  }

  auto pmresult = pm.Run(std::move(ast_root), ctx);
  if (!pmresult.Ok())
    return 1;

  ast_root = std::unique_ptr<ast::Node>(pmresult.Root());

  if (!bpftrace.cmd_.empty())
  {
    try
    {
      bpftrace.child_ = std::make_unique<ChildProc>(args.cmd_str);
    }
    catch (const std::runtime_error& e)
    {
      LOG(ERROR) << "Failed to fork child: " << e.what();
      return -1;
    }
  }

  ast::CodegenLLVM llvm(&*ast_root, bpftrace);
  BpfBytecode bytecode;
  try
  {
    std::unique_ptr<BpfOrc> bpforc;

    llvm.generate_ir();
    if (bt_debug == DebugLevel::kFullDebug)
    {
      std::cout << "Before optimization\n";
      std::cout << "-------------------\n\n";
      llvm.DumpIR();
    }

    llvm.optimize();
    if (bt_debug != DebugLevel::kNone)
    {
      if (bt_debug == DebugLevel::kFullDebug)
      {
        std::cout << "\nAfter optimization\n";
        std::cout << "------------------\n\n";
      }
      llvm.DumpIR();
    }
    if (!args.output_elf.empty())
    {
      llvm.emit_elf(args.output_elf);
      return 0;
    }
    bpforc = llvm.emit();
    if (bt_debug == DebugLevel::kFullDebug)
    {
      std::cout << "\nLLVM JITDLib state\n";
      std::cout << "------------------\n\n";
      raw_os_ostream os(std::cout);
      bpforc->dump(os);
    }

    bytecode = bpforc->getBytecode();
  }
  catch (const std::system_error& ex)
  {
    LOG(ERROR) << "failed to write elf: " << ex.what();
    return 1;
  }
  catch (const std::exception& ex)
  {
    LOG(ERROR) << "Failed to compile: " << ex.what();
    return 1;
  }

  if (bt_debug != DebugLevel::kNone || args.test_mode == TestMode::CODEGEN)
    return 0;

  if (args.build_mode == BuildMode::AHEAD_OF_TIME)
    return aot::generate(bpftrace.resources, bytecode, args.aot);

  // Signal handler that lets us know an exit signal was received.
  struct sigaction act = {};
  act.sa_handler = [](int) { BPFtrace::exitsig_recv = true; };
  sigaction(SIGINT, &act, NULL);
  sigaction(SIGTERM, &act, NULL);

  err = bpftrace.run(bytecode);
  if (err)
    return err;

  // We are now post-processing. If we receive another SIGINT,
  // handle it normally (exit)
  act.sa_handler = SIG_DFL;
  sigaction(SIGINT, &act, NULL);

  std::cout << "\n\n";

  err = bpftrace.print_maps();

  if (bt_verbose && bpftrace.child_)
  {
    auto val = 0;
    if ((val = bpftrace.child_->term_signal()) > -1)
      std::cout << "Child terminated by signal: " << val << std::endl;
    if ((val = bpftrace.child_->exit_code()) > -1)
      std::cout << "Child exited with code: " << val << std::endl;
  }

  if (err)
    return err;

  return 0;
}
