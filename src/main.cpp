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

#include "ast/field_analyser.h"
#include "ast/node_counter.h"
#include "ast/pass_manager.h"
#include "ast/portability_analyser.h"
#include "ast/resource_analyser.h"
#include "ast/semantic_analyser.h"
#include "bpffeature.h"
#include "bpforc.h"
#include "bpftrace.h"
#include "build_info.h"
#include "child.h"
#include "clang_parser.h"
#include "codegen_llvm.h"
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

static int info()
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

  return 0;
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

  ast::FieldAnalyser fields(driver.root_, bpftrace);
  err = fields.analyse();
  if (err)
    return nullptr;

  if (TracepointFormatParser::parse(driver.root_, bpftrace) == false)
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
  if (!include_files.empty() && driver.root_->c_definitions.empty())
    driver.root_->c_definitions = "#define __BPFTRACE_DUMMY__";

  if (!clang.parse(driver.root_, bpftrace, extra_flags))
    return nullptr;

  err = driver.parse();
  if (err)
    return nullptr;

  auto ast = driver.root_;
  driver.root_ = nullptr;
  return std::unique_ptr<ast::Node>(ast);
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

int main(int argc, char* argv[])
{
  int err;
  std::string pid_str;
  std::string cmd_str;
  bool listing = false;
  bool safe_mode = true;
  bool usdt_file_activation = false;
  int helper_check_level = 0;
  TestMode test_mode = TestMode::UNSET;
  std::string script, search, file_name, output_file, output_format, output_elf,
      aot;
  OutputBufferConfig obc = OutputBufferConfig::UNSET;
  BuildMode build_mode = BuildMode::DYNAMIC;
  int c;

  const char* const short_options = "dbB:f:e:hlp:vqc:Vo:I:k";
  option long_options[] = {
    option{ "help", no_argument, nullptr, 'h' },
    option{ "version", no_argument, nullptr, 'V' },
    option{ "usdt-file-activation", no_argument, nullptr, '$' },
    option{ "unsafe", no_argument, nullptr, 'u' },
    option{ "btf", no_argument, nullptr, 'b' },
    option{ "include", required_argument, nullptr, '#' },
    option{ "info", no_argument, nullptr, 2000 },
    option{ "emit-elf", required_argument, nullptr, 2001 },
    option{ "no-warnings", no_argument, nullptr, 2002 },
    option{ "test", required_argument, nullptr, 2003 },
    option{ "aot", required_argument, nullptr, 2004 },
    option{ nullptr, 0, nullptr, 0 }, // Must be last
  };
  std::vector<std::string> include_dirs;
  std::vector<std::string> include_files;
  while ((c = getopt_long(
              argc, argv, short_options, long_options, nullptr)) != -1)
  {
    switch (c)
    {
      case 2000: // --info
        if (is_root())
          return info();
        return 1;
        break;
      case 2001: // --emit-elf
        output_elf = optarg;
        break;
      case 2002: // --no-warnings
        DISABLE_LOG(WARNING);
        break;
      case 2003: // --test
        if (std::strcmp(optarg, "semantic") == 0)
          test_mode = TestMode::SEMANTIC;
        else if (std::strcmp(optarg, "codegen") == 0)
          test_mode = TestMode::CODEGEN;
        else
        {
          LOG(ERROR) << "USAGE: --test must be either 'semantic' or 'codegen'.";
          return 1;
        }
        break;
      case 2004: // --aot
        aot = optarg;
        build_mode = BuildMode::AHEAD_OF_TIME;
        break;
      case 'o':
        output_file = optarg;
        break;
      case 'd':
        bt_debug++;
        if (bt_debug == DebugLevel::kNone) {
          usage();
          return 1;
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
          obc = OutputBufferConfig::LINE;
        } else if (std::strcmp(optarg, "full") == 0) {
          obc = OutputBufferConfig::FULL;
        } else if (std::strcmp(optarg, "none") == 0) {
          obc = OutputBufferConfig::NONE;
        } else {
          LOG(ERROR) << "USAGE: -B must be either 'line', 'full', or 'none'.";
          return 1;
        }
        break;
      case 'f':
        output_format = optarg;
        break;
      case 'e':
        script = optarg;
        break;
      case 'p':
        pid_str = optarg;
        break;
      case 'I':
        include_dirs.push_back(optarg);
        break;
      case '#':
        include_files.push_back(optarg);
        break;
      case 'l':
        listing = true;
        break;
      case 'c':
        cmd_str = optarg;
        break;
      case '$':
        usdt_file_activation = true;
        break;
      case 'u':
        safe_mode = false;
        break;
      case 'b':
        break;
      case 'h':
        usage();
        return 0;
      case 'V':
        std::cout << "bpftrace " << BPFTRACE_VERSION << std::endl;
        return 0;
      case 'k':
        helper_check_level++;
        if (helper_check_level >= 3)
        {
          usage();
          return 1;
        }
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
    LOG(ERROR) << "USAGE: Use either -v or -d.";
    return 1;
  }

  if (!cmd_str.empty() && !pid_str.empty())
  {
    LOG(ERROR) << "USAGE: Cannot use both -c and -p.";
    usage();
    return 1;
  }

  std::ostream * os = &std::cout;
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

  std::unique_ptr<Output> output;
  if (output_format.empty() || output_format == "text") {
    output = std::make_unique<TextOutput>(*os);
  }
  else if (output_format == "json") {
    output = std::make_unique<JsonOutput>(*os);
  }
  else {
    LOG(ERROR) << "Invalid output format \"" << output_format << "\"\n"
               << "Valid formats: 'text', 'json'";
    return 1;
  }

  switch (obc) {
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

  if (!cmd_str.empty())
    bpftrace.cmd_ = cmd_str;

  if (!parse_env(bpftrace))
    return 1;

  // Difficult to serialize flex generated types
  if (helper_check_level && build_mode == BuildMode::AHEAD_OF_TIME)
  {
    LOG(ERROR) << "Cannot use -k[k] with --aot";
    return 1;
  }

  bpftrace.usdt_file_activation_ = usdt_file_activation;
  bpftrace.safe_mode_ = safe_mode;
  bpftrace.helper_check_level_ = helper_check_level;
  bpftrace.boottime_ = get_boottime();

  if (!pid_str.empty())
  {
    try
    {
      bpftrace.procmon_ = std::make_unique<ProcMon>(pid_str);
    }
    catch (const std::exception& e)
    {
      LOG(ERROR) << e.what();
      return 1;
    }
  }

  if (!cmd_str.empty())
  {
    bpftrace.cmd_ = cmd_str;
    try
    {
      bpftrace.child_ = std::make_unique<ChildProc>(cmd_str);
    }
    catch (const std::runtime_error& e)
    {
      LOG(ERROR) << "Failed to fork child: " << e.what();
      return -1;
    }
  }

  // Listing probes
  if (listing)
  {
    if (!is_root())
      return 1;

    if (optind == argc || std::string(argv[optind]) == "*")
      script = "*:*";
    else if (optind == argc - 1)
      script = argv[optind];
    else
    {
      usage();
      return 1;
    }

    if (script.find(':') == std::string::npos &&
        (script.find("struct") == 0 || script.find("union") == 0 ||
         script.find("enum") == 0))
    {
      // Print structure definitions
      bpftrace.probe_matcher_->list_structs(script);
      return 0;
    }

    Driver driver(bpftrace);
    driver.listing_ = true;
    driver.source("stdin", script);

    int err = driver.parse();
    if (err)
      return err;

    ast::SemanticAnalyser semantics(driver.root_, bpftrace, false, true);
    err = semantics.analyse();
    if (err)
      return err;

    bpftrace.probe_matcher_->list_probes(driver.root_);
    return 0;
  }

  std::string filename;
  std::string program;

  if (script.empty())
  {
    // Script file
    if (argv[optind] == nullptr)
    {
      LOG(ERROR) << "USAGE: filename or -e 'program' required.";
      return 1;
    }
    filename = argv[optind];
    std::stringstream buf;

    if (filename == "-")
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
      std::ifstream file(filename);
      if (file.fail())
      {
        LOG(ERROR) << "failed to open file '" << filename
                   << "': " << std::strerror(errno);
        return -1;
      }

      program = buf.str();
      buf << file.rdbuf();
      program = buf.str();
    }

    optind++;
  }
  else
  {
    // Script is provided as a command line argument
    filename = "stdin";
    program = script;
  }

  // Load positional parameters before driver runs so positional
  // parameters used inside attach point definitions can be resolved.
  while (optind < argc)
  {
    bpftrace.add_param(argv[optind]);
    optind++;
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
      bpftrace, filename, program, include_dirs, include_files);
  if (!ast_root)
    return 1;

  ast::PassContext ctx(bpftrace);
  ast::PassManager pm;
  switch (build_mode)
  {
    case BuildMode::DYNAMIC:
      pm = CreateDynamicPM();
      break;
    case BuildMode::AHEAD_OF_TIME:
      pm = CreateAotPM(aot);
      break;
  }
  ast_root = pm.Run(std::move(ast_root), ctx);
  if (!ast_root)
    return 1;

  if (!bpftrace.cmd_.empty())
  {
    try
    {
      bpftrace.child_ = std::make_unique<ChildProc>(cmd_str);
    }
    catch (const std::runtime_error& e)
    {
      LOG(ERROR) << "Failed to fork child: " << e.what();
      return -1;
    }
  }

  ast::CodegenLLVM llvm(&*ast_root, bpftrace);
  std::unique_ptr<BpfOrc> bpforc;
  try
  {
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
    if (!output_elf.empty())
    {
      llvm.emit_elf(output_elf);
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

  if (bt_debug != DebugLevel::kNone || test_mode == TestMode::CODEGEN ||
      build_mode == BuildMode::AHEAD_OF_TIME)
    return 0;

  // Signal handler that lets us know an exit signal was received.
  struct sigaction act = {};
  act.sa_handler = [](int) { BPFtrace::exitsig_recv = true; };
  sigaction(SIGINT, &act, NULL);
  sigaction(SIGTERM, &act, NULL);

  uint64_t num_probes = bpftrace.num_probes();
  if (num_probes == 0)
  {
    if (!bt_quiet)
      std::cout << "No probes to attach" << std::endl;
    return 1;
  }
  else if (num_probes > bpftrace.max_probes_)
  {
    LOG(ERROR)
        << "Can't attach to " << num_probes << " probes because it "
        << "exceeds the current limit of " << bpftrace.max_probes_
        << " probes.\n"
        << "You can increase the limit through the BPFTRACE_MAX_PROBES "
        << "environment variable, but BE CAREFUL since a high number of probes "
        << "attached can cause your system to crash.";
    return 1;
  }
  else if (!bt_quiet)
    bpftrace.out_->attached_probes(num_probes);

  err = bpftrace.run(move(bpforc));
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
