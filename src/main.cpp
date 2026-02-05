#include <bpf/libbpf.h>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "aot/aot.h"
#include "ast/diagnostic.h"
#include "ast/helpers.h"
#include "ast/pass_manager.h"
#include "ast/passes/attachpoint_passes.h"
#include "ast/passes/clang_build.h"
#include "ast/passes/clang_parser.h"
#include "ast/passes/codegen_llvm.h"
#include "ast/passes/control_flow_analyser.h"
#include "ast/passes/macro_expansion.h"
#include "ast/passes/map_sugar.h"
#include "ast/passes/named_param.h"
#include "ast/passes/parser.h"
#include "ast/passes/pid_filter_pass.h"
#include "ast/passes/portability_analyser.h"
#include "ast/passes/printer.h"
#include "ast/passes/recursion_check.h"
#include "ast/passes/resource_analyser.h"
#include "ast/passes/type_checker.h"
#include "ast/passes/type_resolver.h"
#include "ast/passes/type_system.h"
#include "ast/passes/variable_precheck.h"
#include "benchmark.h"
#include "bpffeature.h"
#include "bpftrace.h"
#include "btf.h"
#include "build_info.h"
#include "config.h"
#include "globalvars.h"
#include "lockdown.h"
#include "log.h"
#include "output/buffer_mode.h"
#include "probe_matcher.h"
#include "run_bpftrace.h"
#include "symbols/kernel.h"
#include "symbols/user.h"
#include "util/env.h"
#include "util/int_parser.h"
#include "util/proc.h"
#include "util/strings.h"
#include "util/temp.h"
#include "version.h"

using namespace bpftrace;

namespace {

enum class Mode {
  NONE = 0,
  CODEGEN,
  COMPILER_BENCHMARK,
  BPF_BENCHMARK,
  BPF_TEST,
  FORMAT,
};

enum class BuildMode {
  // Compile script and run immediately
  DYNAMIC = 0,
  // Compile script into portable executable
  AHEAD_OF_TIME,
};

enum Options {
  AOT = 2000,
  BENCH, // Alias for --mode=bench.
  BTF,
  CMD,
  DEBUG,
  DRY_RUN,
  EMIT_ELF,
  EMIT_LLVM,
  FMT, // Alias for --mode=format.
  HELP,
  INCLUDE,
  INFO,
  LIST,
  NO_FEATURE,
  NO_WARNING,
  MODE,
  OUTPUT,
  PID,
  QUIET,
  TEST, // Alias for --mode=test.
  UNSAFE,
  USDT_SEMAPHORE,
  VERBOSE,
  VERIFY_LLVM_IR,
  VERSION,
  WARNINGS,
};

constexpr auto FULL_SEARCH = "*:*";

} // namespace

void usage(std::ostream& out)
{
  // clang-format off
  out << "USAGE:" << std::endl;
  out << "    bpftrace [options] filename" << std::endl;
  out << "    bpftrace [options] - <stdin input>" << std::endl;
  out << "    bpftrace [options] -e 'program'" << std::endl;
  out << std::endl;
  out << "OPTIONS:" << std::endl;
  out << "    -B MODE        output buffering mode ('line', 'full', 'none')" << std::endl;
  out << "    -f FORMAT      output format ('text', 'json')" << std::endl;
  out << "    -o, --output FILE" << std::endl;
  out << "                   redirect bpftrace output to FILE" << std::endl;
  out << "    -e 'program'   execute this program" << std::endl;
  out << "    -h, --help     show this help message" << std::endl;
  out << "    -I DIR         add the directory to the include search path" << std::endl;
  out << "    --include FILE add an #include file before preprocessing" << std::endl;
  out << "    -l, --list [search|filename]" << std::endl;
  out << "                   list kernel probes or probes in a program" << std::endl;
  out << "    -p, --pid PID  filter actions and enable USDT probes on PID" << std::endl;
  out << "    -c, --cmd CMD  run CMD and enable USDT probes on resulting process" << std::endl;
  out << "    --no-feature FEATURE[,FEATURE]" << std::endl;
  out << "                   disable use of detected features" << std::endl;
  out << "    --usdt-file-activation" << std::endl;
  out << "                   activate usdt semaphores based on file path" << std::endl;
  out << "    --unsafe       allow unsafe/destructive functionality" << std::endl;
  out << "    -q, --quiet    keep messages quiet" << std::endl;
  out << "    --info         Print information about kernel BPF support" << std::endl;
  out << "    -k, --warnings emit a warning when probe read helpers return an error" << std::endl;
  out << "    -V, --version  bpftrace version" << std::endl;
  out << "    --no-warnings  disable all warning messages" << std::endl;
  out << "    --mode MODE    used for benchmarking and testing" << std::endl;
  out << "                   ('codegen', 'compiler-bench', 'bench', 'test', 'format')" << std::endl;
  out << "    --test         run all test: probes (same as --mode test)" << std::endl;
  out << "    --bench        run all bench: probes (same as --mode bench)" << std::endl;
  out << std::endl;
  out << "TROUBLESHOOTING OPTIONS:" << std::endl;
  out << "    -v, --verbose           verbose messages" << std::endl;
  out << "    --dry-run               terminate execution right after attaching all the probes" << std::endl;
  out << "    --verify-llvm-ir        check that the generated LLVM IR is valid" << std::endl;
  out << "    -d, --debug STAGE       debug info for various stages of bpftrace execution" << std::endl;
  out << "                            ('all', 'ast', 'types', 'codegen', 'codegen-opt', 'dis', 'libbpf', 'verifier')" << std::endl;
  out << "    --emit-elf FILE         (dry run) generate ELF file with bpf programs and write to FILE" << std::endl;
  out << "    --emit-llvm FILE        write LLVM IR to FILE.original.ll and FILE.optimized.ll" << std::endl;
  out << std::endl;
  out << "ENVIRONMENT:" << std::endl;
  out << "    BPFTRACE_BTF                      [default: none] BTF file" << std::endl;
  out << "    BPFTRACE_CACHE_USER_SYMBOLS       [default: auto] enable user symbol cache" << std::endl;
  out << "    BPFTRACE_COLOR                    [default: auto] enable log output colorization" << std::endl;
  out << "    BPFTRACE_CPP_DEMANGLE             [default: 1] enable C++ symbol demangling" << std::endl;
  out << "    BPFTRACE_KERNEL_BUILD             [default: /lib/modules/$(uname -r)] kernel build directory" << std::endl;
  out << "    BPFTRACE_KERNEL_SOURCE            [default: /lib/modules/$(uname -r)] kernel headers directory" << std::endl;
  out << "    BPFTRACE_LAZY_SYMBOLICATION       [default: 0] symbolicate lazily/on-demand" << std::endl;
  out << "    BPFTRACE_LOG_SIZE                 [default: 1000000] log size in bytes" << std::endl;
  out << "    BPFTRACE_MAX_BPF_PROGS            [default: 1024] max number of generated BPF programs" << std::endl;
  out << "    BPFTRACE_MAX_CAT_BYTES            [default: 10k] maximum bytes read by cat builtin" << std::endl;
  out << "    BPFTRACE_MAX_MAP_KEYS             [default: 4096] max keys in a map" << std::endl;
  out << "    BPFTRACE_MAX_PROBES               [default: 1024] max number of probes" << std::endl;
  out << "    BPFTRACE_MAX_STRLEN               [default: 1024] bytes on BPF stack per str()" << std::endl;
  out << "    BPFTRACE_MAX_TYPE_RES_ITERATIONS  [default: 0] number of levels of nested field accesses for tracepoint args" << std::endl;
  out << "    BPFTRACE_PERF_RB_PAGES            [default: 64] pages per CPU to allocate for ring buffer" << std::endl;
  out << "    BPFTRACE_STACK_MODE               [default: bpftrace] Output format for ustack and kstack builtins" << std::endl;
  out << "    BPFTRACE_STR_TRUNC_TRAILER        [default: '..'] string truncation trailer" << std::endl;
  out << "    BPFTRACE_VMLINUX                  [default: none] vmlinux path used for kernel symbol resolution" << std::endl;
  out << std::endl;
  out << "EXAMPLES:" << std::endl;
  out << "bpftrace -l '*sleep*'" << std::endl;
  out << "    list probes containing \"sleep\"" << std::endl;
  out << R"(bpftrace -e 'kprobe:do_nanosleep { printf("PID %d sleeping...\n", pid); }')" << std::endl;
  out << "    trace processes calling sleep" << std::endl;
  out << "bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'" << std::endl;
  out << "    count syscalls by process name" << std::endl;
  // clang-format on
}

static void enforce_infinite_rlimit_memlock()
{
  struct rlimit rl = {};
  int err;

  rl.rlim_max = RLIM_INFINITY;
  rl.rlim_cur = rl.rlim_max;
  err = setrlimit(RLIMIT_MEMLOCK, &rl);
  if (err)
    LOG(WARNING) << std::strerror(err) << ": couldn't set RLIMIT_MEMLOCK for "
                 << "bpftrace. If your program is not loading, you can try "
                 << "\"ulimit -l 8192\" to fix the problem";
}

static void info(BPFnofeature no_feature)
{
  struct utsname utsname;
  uname(&utsname);

  auto btf = bpftrace::BTF();

  std::cout << "System" << std::endl
            << "  OS: " << utsname.sysname << " " << utsname.release << " "
            << utsname.version << std::endl
            << "  Arch: " << utsname.machine << std::endl;

  std::cout << std::endl;
  std::cout << BuildInfo::report();

  std::cout << std::endl;
  std::cout << BPFfeature(no_feature, btf).report();
}

static std::optional<struct timespec> get_delta_with_boottime(int clock_type)
{
  std::optional<struct timespec> ret = std::nullopt;
  long lowest_delta = std::numeric_limits<long>::max();

  // Run the "triple vdso sandwich" 5 times, taking the result from the
  // iteration with the lowest delta between first and last clock_gettime()
  // calls.
  for (int i = 0; i < 5; ++i) {
    struct timespec before, after, boottime;
    long delta;

    if (::clock_gettime(clock_type, &before))
      continue;

    if (::clock_gettime(CLOCK_BOOTTIME, &boottime))
      continue;

    if (::clock_gettime(clock_type, &after))
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
    if (delta < lowest_delta) {
      struct timespec delta_with_boottime;
      long nsec_avg = (before.tv_nsec + after.tv_nsec) / 2;
      if (nsec_avg - boottime.tv_nsec < 0) {
        delta_with_boottime.tv_sec = after.tv_sec - boottime.tv_sec - 1;
        delta_with_boottime.tv_nsec = nsec_avg - boottime.tv_nsec + 1e9;
      } else {
        delta_with_boottime.tv_sec = after.tv_sec - boottime.tv_sec;
        delta_with_boottime.tv_nsec = nsec_avg - boottime.tv_nsec;
      }

      lowest_delta = delta;
      ret = delta_with_boottime;
    }
  }

  if (ret && lowest_delta >= 1e5)
    LOG(WARNING) << (lowest_delta / 1e3)
                 << "us skew detected when calculating boot time. strftime() "
                    "builtin may be inaccurate";

  return ret;
}

static std::optional<struct timespec> get_boottime()
{
  return get_delta_with_boottime(CLOCK_REALTIME);
}

static std::optional<struct timespec> get_delta_taitime()
{
  return get_delta_with_boottime(CLOCK_TAI);
}

std::vector<std::string> extra_flags(
    BPFtrace& bpftrace,
    const std::vector<std::string>& include_dirs,
    const std::vector<std::string>& include_files)
{
  std::string ksrc, kobj;
  struct utsname utsname;
  std::vector<std::string> extra_flags;
  uname(&utsname);
  bool found_kernel_headers = symbols::get_kernel_dirs(utsname, ksrc, kobj);

  if (found_kernel_headers)
    extra_flags = get_kernel_cflags(
        utsname.machine, ksrc, kobj, bpftrace.kconfig);

  for (auto dir : include_dirs) {
    extra_flags.emplace_back("-I");
    extra_flags.push_back(dir);
  }
  for (auto file : include_files) {
    extra_flags.emplace_back("-include");
    extra_flags.push_back(file);
  }

  return extra_flags;
}

struct Args {
  std::string pid_str;
  std::string cmd_str;
  bool listing = false;
  bool safe_mode = true;
  bool usdt_file_activation = false;
  int warning_level = 1;
  bool verify_llvm_ir = false;
  Mode mode = Mode::NONE;
  std::string script;
  std::string search;
  std::string filename;
  std::string output_file;
  std::string output_format;
  std::string output_elf;
  std::string output_llvm;
  std::string aot;
  BPFnofeature no_feature;
  OutputBufferConfig obc = OutputBufferConfig::UNSET;
  BuildMode build_mode = BuildMode::DYNAMIC;
  std::vector<std::string> include_dirs;
  std::vector<std::string> include_files;
  std::vector<std::string> params;
  std::vector<std::string> debug_stages;
  std::vector<std::string> named_params;
};

void CreateDynamicPasses(std::function<void(ast::Pass&& pass)> add)
{
  add(ast::CreateClangBuildPass());
  add(ast::CreateTypeSystemPass());
  add(ast::CreateVariablePreCheckPass());
  add(ast::CreateTypeResolverPass());
  add(ast::CreateTypeCheckerPass());
  add(ast::CreateResourcePass());
}

void CreateAotPasses(std::function<void(ast::Pass&& pass)> add)
{
  add(ast::CreatePortabilityPass());
  add(ast::CreateClangBuildPass());
  add(ast::CreateTypeSystemPass());
  add(ast::CreateVariablePreCheckPass());
  add(ast::CreateTypeResolverPass());
  add(ast::CreateTypeCheckerPass());
  add(ast::CreateResourcePass());
}

ast::Pass printPass(const std::string& name)
{
  return ast::Pass::create("print-" + name, [=](ast::ASTContext& ast) {
    std::cerr << "AST after: " << name << std::endl;
    std::cerr << "-------------------" << std::endl;
    ast::Printer printer(ast, std::cerr);
    printer.visit(ast.root);
    std::cerr << std::endl;
  });
};

static bool parse_debug_stages(const std::string& arg)
{
  auto stages = util::split_string(arg, ',', /* remove_empty= */ true);

  for (const auto& stage : stages) {
    if (debug_stages.contains(stage)) {
      bt_debug.insert(debug_stages.at(stage));
    } else if (stage == "all") {
      for (const auto& [_, s] : debug_stages)
        bt_debug.insert(s);
    } else {
      LOG(ERROR) << "USAGE: invalid option for -d: " << stage;
      return false;
    }
  }

  return true;
}

Args parse_args(int argc, char* argv[])
{
  Args args;

  const char* const short_options = "d:bB:f:e:hlp:vqc:Vo:I:k";
  option long_options[] = {
    option{ .name = "aot",
            .has_arg = required_argument,
            .flag = nullptr,
            .val = Options::AOT },
    option{ .name = "bench",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::BENCH },
    option{ .name = "btf",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::BTF },
    option{ .name = "cmd",
            .has_arg = required_argument,
            .flag = nullptr,
            .val = Options::CMD },
    option{ .name = "debug",
            .has_arg = required_argument,
            .flag = nullptr,
            .val = Options::DEBUG },
    option{ .name = "dry-run",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::DRY_RUN },
    option{ .name = "emit-elf",
            .has_arg = required_argument,
            .flag = nullptr,
            .val = Options::EMIT_ELF },
    option{ .name = "emit-llvm",
            .has_arg = required_argument,
            .flag = nullptr,
            .val = Options::EMIT_LLVM },
    option{ .name = "fmt",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::FMT },
    option{ .name = "help",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::HELP },
    option{ .name = "include",
            .has_arg = required_argument,
            .flag = nullptr,
            .val = Options::INCLUDE },
    option{ .name = "info",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::INFO },
    option{ .name = "list",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::LIST },
    option{ .name = "no-feature",
            .has_arg = required_argument,
            .flag = nullptr,
            .val = Options::NO_FEATURE },
    option{ .name = "no-warnings",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::NO_WARNING },
    option{ .name = "output",
            .has_arg = required_argument,
            .flag = nullptr,
            .val = Options::OUTPUT },
    option{ .name = "pid",
            .has_arg = required_argument,
            .flag = nullptr,
            .val = Options::PID },
    option{ .name = "quiet",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::QUIET },
    option{ .name = "test",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::TEST },
    option{ .name = "mode",
            .has_arg = required_argument,
            .flag = nullptr,
            .val = Options::MODE },
    option{ .name = "unsafe",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::UNSAFE },
    option{ .name = "usdt-file-activation",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::USDT_SEMAPHORE },
    option{ .name = "verbose",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::VERBOSE },
    option{ .name = "verify-llvm-ir",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::VERIFY_LLVM_IR },
    option{ .name = "version",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::VERSION },
    option{ .name = "warnings",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::WARNINGS },
    option{ .name = nullptr, .has_arg = 0, .flag = nullptr, .val = 0 }, // Must
                                                                        // be
                                                                        // last
  };

  int c;
  while ((c = getopt_long(argc, argv, short_options, long_options, nullptr)) !=
         -1) {
    switch (c) {
      case Options::INFO: // --info
        check_privileges();
        info(args.no_feature);
        exit(0);
        break;
      case Options::EMIT_ELF: // --emit-elf
        args.output_elf = optarg;
        break;
      case Options::EMIT_LLVM:
        args.output_llvm = optarg;
        break;
      case Options::NO_WARNING: // --no-warnings
        if (args.warning_level == 2) {
          LOG(ERROR) << "USAGE: -k, --warnings conflicts with --no-warnings";
          exit(1);
        }
        DISABLE_LOG(WARNING);
        args.warning_level = 0;
        break;
      case Options::MODE: // --mode
        if (std::strcmp(optarg, "codegen") == 0) {
          args.mode = Mode::CODEGEN;
        } else if (std::strcmp(optarg, "compiler-bench") == 0) {
          args.mode = Mode::COMPILER_BENCHMARK;
        } else if (std::strcmp(optarg, "bench") == 0) {
          args.mode = Mode::BPF_BENCHMARK;
        } else if (std::strcmp(optarg, "test") == 0) {
          args.mode = Mode::BPF_TEST;
        } else if (std::strcmp(optarg, "format") == 0) {
          args.mode = Mode::FORMAT;
        } else {
          LOG(ERROR) << "USAGE: --mode can only be 'codegen', "
                        "'compiler-bench', 'bench', 'test' or 'format'.";
          exit(1);
        }
        break;
      case Options::TEST: // --test
        if (args.mode != Mode::NONE) {
          LOG(ERROR) << "USAGE: --test conflicts with existing --mode";
          exit(1);
        }
        args.mode = Mode::BPF_TEST;
        break;
      case Options::BENCH: // --bench
        if (args.mode != Mode::NONE) {
          LOG(ERROR) << "USAGE: --bench conflicts with existing --mode";
          exit(1);
        }
        args.mode = Mode::BPF_BENCHMARK;
        break;
      case Options::FMT: // --fmt
        if (args.mode != Mode::NONE) {
          LOG(ERROR) << "USAGE: --fmt conflicts with existing --mode";
          exit(1);
        }
        args.mode = Mode::FORMAT;
        break;
      case Options::AOT: // --aot
        args.aot = optarg;
        args.build_mode = BuildMode::AHEAD_OF_TIME;
        break;
      case Options::NO_FEATURE: // --no-feature
        if (args.no_feature.parse(optarg)) {
          LOG(ERROR) << "USAGE: --no-feature can only have values "
                        "'kprobe_multi,kprobe_session,uprobe_multi'.";
          exit(1);
        }
        break;
      case Options::DRY_RUN:
        dry_run = true;
        break;
      case Options::VERIFY_LLVM_IR:
        args.verify_llvm_ir = true;
        break;
      case 'o':
      case Options::OUTPUT:
        args.output_file = optarg;
        break;
      case 'd':
      case Options::DEBUG:
        if (!parse_debug_stages(optarg))
          exit(1);
        break;
      case 'q':
      case Options::QUIET:
        bt_quiet = true;
        break;
      case 'v':
      case Options::VERBOSE:
        ENABLE_LOG(V1);
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
      case Options::PID:
        args.pid_str = optarg;
        break;
      case 'I':
        args.include_dirs.emplace_back(optarg);
        break;
      case Options::INCLUDE:
        args.include_files.emplace_back(optarg);
        break;
      case 'l':
      case Options::LIST:
        args.listing = true;
        break;
      case 'c':
      case Options::CMD:
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
        usage(std::cout);
        exit(0);
      case 'V':
      case Options::VERSION:
        std::cout << "bpftrace " << BPFTRACE_VERSION << std::endl;
        exit(0);
      case 'k':
      case Options::WARNINGS:
        if (args.warning_level == 2) {
          LOG(ERROR) << "USAGE: -kk has been deprecated. Use a single -k for "
                        "runtime warnings for errors in map "
                        "lookups and probe reads.";
          exit(1);
        }
        if (args.warning_level == 0) {
          LOG(ERROR) << "USAGE: -k, --warnings conflicts with --no-warnings";
          exit(1);
        }
        args.warning_level = 2;
        break;
      default:
        usage(std::cerr);
        exit(1);
    }
  }

  if (argc == 1) {
    usage(std::cerr);
    exit(1);
  }

  if (!args.cmd_str.empty() && !args.pid_str.empty()) {
    LOG(ERROR) << "USAGE: Cannot use both -c and -p.";
    usage(std::cerr);
    exit(1);
  }

  // Difficult to serialize flex generated types
  if (args.warning_level == 2 && args.build_mode == BuildMode::AHEAD_OF_TIME) {
    LOG(ERROR) << "Cannot use -k with --aot";
    exit(1);
  }

  if (args.listing) {
    // Expect zero or one positional arguments
    if (optind == argc) {
      args.search = FULL_SEARCH;
    } else if (optind == argc - 1) {
      std::string val(argv[optind]);
      if (std::filesystem::exists(val)) {
        args.filename = val;
      } else {
        if (val == "*") {
          args.search = FULL_SEARCH;
        } else {
          args.search = val;
        }
      }
      optind++;
    } else {
      usage(std::cerr);
      exit(1);
    }
  } else {
    // Expect to find a script either through -e or filename
    if (args.script.empty() && argv[optind] == nullptr) {
      LOG(ERROR) << "USAGE: filename or -e 'program' required.";
      exit(1);
    }

    // If no script was specified with -e, then we expect to find a script file
    if (args.script.empty()) {
      args.filename = argv[optind];
      optind++;
    }

    // Parse positional and named parameters.
    while (optind < argc) {
      auto pos_arg = std::string(argv[optind]);
      if (pos_arg.starts_with("--")) {
        args.named_params.emplace_back(pos_arg.substr(2));
      } else {
        args.params.emplace_back(argv[optind]);
      }
      optind++;
    }
  }
  return args;
}

bool is_colorize()
{
  const char* color_env = std::getenv("BPFTRACE_COLOR");
  if (!color_env) {
    return isatty(STDOUT_FILENO) && isatty(STDERR_FILENO);
  }

  std::string_view mode(color_env);
  if (mode == "always") {
    return true;
  } else if (mode == "never") {
    return false;
  } else {
    if (mode != "auto") {
      LOG(WARNING) << "Invalid env value! The valid values of `BPFTRACE_COLOR` "
                      "are [auto|always|never]. The current value is "
                   << mode << "!";
    }
    return isatty(STDOUT_FILENO) && isatty(STDERR_FILENO);
  }
}

int main(int argc, char* argv[])
{
  Log::get().set_colorize(is_colorize());
  Args args = parse_args(argc, argv);

  switch (args.obc) {
    case OutputBufferConfig::UNSET:
    case OutputBufferConfig::LINE:
      std::setvbuf(stdout, nullptr, _IOLBF, BUFSIZ);
      break;
    case OutputBufferConfig::FULL:
      std::setvbuf(stdout, nullptr, _IOFBF, BUFSIZ);
      break;
    case OutputBufferConfig::NONE:
      std::setvbuf(stdout, nullptr, _IONBF, BUFSIZ);
      break;
  }

  libbpf_set_print(libbpf_print);

  auto config = std::make_unique<Config>(!args.cmd_str.empty());
  BPFtrace bpftrace(args.no_feature, std::move(config));

  // Create function info objects for probe matching and pass state.
  auto kernel_func_info = symbols::KernelInfoImpl::open();
  if (!kernel_func_info) {
    LOG(ERROR) << "Failed to open kernel function info: "
               << kernel_func_info.takeError();
    return 1;
  }
  symbols::UserInfoImpl user_func_info;
  ast::FunctionInfo func_info_state(*kernel_func_info, user_func_info);

  bpftrace.usdt_file_activation_ = args.usdt_file_activation;
  bpftrace.safe_mode_ = args.safe_mode;
  bpftrace.warning_level_ = args.warning_level;
  bpftrace.boottime_ = get_boottime();
  bpftrace.delta_taitime_ = get_delta_taitime();
  bpftrace.run_tests_ = args.mode == Mode::BPF_TEST;
  bpftrace.run_benchmarks_ = args.mode == Mode::BPF_BENCHMARK;

  if (!args.pid_str.empty()) {
    auto maybe_pid = util::to_uint(args.pid_str);
    if (!maybe_pid) {
      LOG(ERROR) << "Failed to parse pid: " << maybe_pid.takeError();
      exit(1);
    }
    if (*maybe_pid > 0x400000) {
      // The actual maximum pid depends on the configuration for the specific
      // system, i.e. read from `/proc/sys/kernel/pid_max`. We can impose a
      // basic sanity check here against the nominal maximum for 64-bit
      // systems.
      LOG(ERROR) << "Pid out of range: " << *maybe_pid;
      exit(1);
    }
    auto proc = util::create_proc(*maybe_pid);
    if (!proc) {
      LOG(ERROR) << "Failed to attach to pid: " << proc.takeError();
      exit(1);
    }
    bpftrace.procmon_ = std::move(*proc);
  }

  if (!args.cmd_str.empty()) {
    bpftrace.cmd_ = args.cmd_str;
    auto child = util::create_child(args.cmd_str);
    if (!child) {
      LOG(ERROR) << "Failed to fork child: " << child.takeError();
      exit(1);
    }
    bpftrace.child_ = std::move(*child);
  }

  // This is our primary program AST context. Initially it is empty, i.e.
  // there is no filename set or source file. The way we set it up depends on
  // the mode of execution below, and we expect that it will be reinitialized.
  ast::ASTContext ast;

  // Listing probes when there is no program.
  if (args.listing && args.script.empty() && args.filename.empty()) {
    check_privileges();

    if (args.search.find(".") != std::string::npos &&
        args.search.find_first_of(":*") == std::string::npos) {
      LOG(WARNING)
          << "It appears that \'" << args.search
          << "\' is a filename but the file does not exist. Treating \'"
          << args.search << "\' as a search pattern.";
    }

    bool is_search_a_type = is_type_name(args.search);

    // Ensure that BTF is loaded for all listing.
    auto parts = util::split_string(args.search, ':');
    if (is_search_a_type || parts.empty() || parts.size() < 3) {
      bpftrace.btf_->load_module_btfs(kernel_func_info->get_modules());
    } else {
      bpftrace.btf_->load_module_btfs(kernel_func_info->get_modules(parts[1]));
    }

    // Use ProbeMatcher directly to list probes matching the search pattern.
    ProbeMatcher probe_matcher(&bpftrace, *kernel_func_info, user_func_info);
    if (is_search_a_type) {
      for (const auto& s : probe_matcher.get_structs_for_listing(args.search)) {
        std::cout << s << std::endl;
      }
    } else {
      // For patterns without a colon (like "*do_nanosleep*"), treat as
      // wildcard probe type with the pattern as function match.
      std::string search = args.search;
      if (search.empty()) {
        search = "*:*";
      } else if (search.find(':') == std::string::npos) {
        search = "*:" + search;
      }
      for (const auto& probe :
           probe_matcher.get_probes_for_listing(search, bpftrace.pid())) {
        std::cout << probe << std::endl;
      }
    }

    return 0;
  }

  if (!args.filename.empty()) {
    std::stringstream buf;

    if (args.filename == "-") {
      std::string line;
      while (std::getline(std::cin, line)) {
        // Note we may add an extra newline if the input doesn't end in a new
        // line. This should not matter because bpftrace (the language) is not
        // whitespace sensitive.
        buf << line << std::endl;
      }

      ast = ast::ASTContext("stdin", buf.str());
    } else {
      std::ifstream file(args.filename);
      if (file.fail()) {
        LOG(ERROR) << "failed to open file '" << args.filename
                   << "': " << std::strerror(errno);
        exit(1);
      }

      buf << file.rdbuf();
      ast = ast::ASTContext(args.filename, buf.str());
    }
  } else {
    // Script is provided as a command line argument.
    ast = ast::ASTContext("stdin", args.script);
  }

  if (args.mode == Mode::FORMAT) {
    // For formatting, we parse the full file, but don't apply any other passes
    // or use any other diagnostics. It only matters whether the parse itself
    // was successful, and then we emit the formatted source code.
    ast::PassManager pm;
    pm.put(ast);
    pm.put(bpftrace);
    pm.add(CreateParsePass(bt_debug.contains(DebugStage::Parse)));
    auto ok = pm.run();
    if (!ok) {
      std::cerr << ok.takeError() << "\n";
      return 2;
    }
    if (!ast.diagnostics().ok()) {
      // We didn't successfully parse the file, so can't format it.
      ast.diagnostics().emit(std::cerr);
      return 1;
    }
    if (!args.output_file.empty()) {
      // To make this operation safe, we open a temporary file next to the
      // intented output file, and atomically rename when completed.
      auto file = util::TempFile::create(args.output_file + ".XXXXXX");
      if (!file) {
        LOG(ERROR) << "unable to create temporary file: " << file.takeError();
        return 1;
      }
      std::ofstream out(file->path());
      if (out.fail()) {
        LOG(ERROR) << "failed to open file '" << file->path()
                   << "': " << std::strerror(errno);
        return 1;
      }
      ast::Printer printer(ast, out, ast::FormatMode::Full);
      printer.visit(ast.root);
      std::filesystem::rename(file->path(), args.output_file);
    } else {
      ast::Printer printer(ast, std::cout, ast::FormatMode::Full);
      printer.visit(ast.root);
    }
    return 0; // All done.
  }

  for (const auto& param : args.params) {
    bpftrace.add_param(param);
  }

  // If we are not running anything, then we don't require privileges.
  if (args.mode == Mode::NONE || args.mode == Mode::BPF_TEST ||
      args.mode == Mode::BPF_BENCHMARK) {
    check_privileges();

    auto lockdown_state = lockdown::detect();
    if (lockdown_state == lockdown::LockdownState::Confidentiality) {
      lockdown::emit_warning(std::cerr);
      return 1;
    }

    // FIXME (mmarchini): maybe we don't want to always enforce an infinite
    // rlimit?
    enforce_infinite_rlimit_memlock();
  }

  // Temporarily, we make the full `BPFTrace` object available via the pass
  // manager (and objects are temporarily mutable). As passes are refactored
  // into lighter-weight components, the `BPFTrace` object should be
  // decomposed into its meaningful parts. Furthermore, the codegen and field
  // analysis passes will be rolled into the pass manager as regular passes;
  // the final binary is merely one of the outputs that can be extracted.
  ast::PassManager pm;
  pm.put(ast);
  pm.put(bpftrace);
  pm.put(func_info_state);
  auto flags = extra_flags(bpftrace, args.include_dirs, args.include_files);

  if (args.listing) {
    // For listing with a program, run the full parse passes (including
    // expansion) and then use ProbeMatcher to expand and list probes.
    for (auto& pass : ast::AllParsePasses(
             std::move(flags), {}, bt_debug.contains(DebugStage::Parse))) {
      pm.add(std::move(pass));
    }

    auto pmresult = pm.run();
    if (!pmresult) {
      std::cerr << pmresult.takeError() << "\n";
      return 2;
    } else if (!ast.diagnostics().ok()) {
      ast.diagnostics().emit(std::cerr);
      return 1;
    }

    // Use ProbeMatcher to expand and list the probes.
    ProbeMatcher probe_matcher(&bpftrace, *kernel_func_info, user_func_info);
    for (const auto& probe : probe_matcher.get_probes_for_listing(ast.root)) {
      std::cout << probe << std::endl;
    }
    return 0;
  }

  // Wrap all added passes in passes that dump the intermediate state. These
  // could dump intermediate objects from the context as well, but preserve
  // existing behavior for now.
  auto addPass = [&pm](ast::Pass&& pass) {
    auto name = pass.name();
    pm.add(std::move(pass));
    if (bt_debug.contains(DebugStage::Ast)) {
      pm.add(printPass(name));
    }
  };
  // Start with all the basic parsing steps.
  for (auto& pass : ast::AllParsePasses(std::move(flags),
                                        {},
                                        bt_debug.contains(DebugStage::Parse))) {
    addPass(std::move(pass));
  }
  pm.add(ast::CreateLLVMInitPass());

  switch (args.build_mode) {
    case BuildMode::DYNAMIC:
      CreateDynamicPasses(addPass);
      break;
    case BuildMode::AHEAD_OF_TIME:
      CreateAotPasses(addPass);
      break;
  }

  if (bt_debug.contains(DebugStage::Types)) {
    pm.add(ast::CreateDumpTypesPass(std::cout));
  }
  pm.add(ast::CreateCompilePass());
  pm.add(ast::CreateLinkBitcodePass());
  if (bt_debug.contains(DebugStage::Codegen)) {
    pm.add(ast::Pass::create("dump-ir-prefix", [&] {
      std::cout << "LLVM IR before optimization\n";
      std::cout << "---------------------------\n\n";
    }));
    pm.add(ast::CreateDumpIRPass(std::cout));
  }
  std::optional<std::ofstream> output_ir;
  if (!args.output_llvm.empty()) {
    output_ir = std::ofstream(args.output_llvm + ".original.ll");
    pm.add(ast::CreateDumpIRPass(*output_ir));
  }
  if (args.verify_llvm_ir) {
    pm.add(ast::CreateVerifyPass());
  }
  pm.add(ast::CreateOptimizePass());
  if (bt_debug.contains(DebugStage::CodegenOpt)) {
    pm.add(ast::Pass::create("dump-ir-opt-prefix", [&] {
      std::cout << "\nLLVM IR after optimization\n";
      std::cout << "----------------------------\n\n";
    }));
    pm.add(ast::CreateDumpIRPass(std::cout));
  }
  std::optional<std::ofstream> output_ir_opt;
  if (!args.output_llvm.empty()) {
    output_ir_opt = std::ofstream(args.output_llvm + ".optimized.ll");
    pm.add(ast::CreateDumpIRPass(*output_ir_opt));
  }
  pm.add(ast::CreateObjectPass());
  if (bt_debug.contains(DebugStage::Disassemble)) {
    pm.add(ast::Pass::create("dump-asm-prefix", [&] {
      std::cout << "\nDisassembled bytecode\n";
      std::cout << "----------------------------\n\n";
    }));
    pm.add(ast::CreateDumpASMPass(std::cout));
  }
  if (!args.output_elf.empty()) {
    pm.add(ast::Pass::create("dump-elf", [&](ast::BpfObject& obj) {
      std::ofstream out(args.output_elf);
      out.write(obj.data.data(), obj.data.size());
    }));
  }
  pm.add(ast::CreateExternObjectPass());
  pm.add(ast::CreateLinkPass());

  if (args.mode == Mode::COMPILER_BENCHMARK) {
    info(args.no_feature);
    auto ok = benchmark(std::cout, pm);
    if (!ok) {
      std::cerr << "Benchmark error: " << ok.takeError();
      return 1;
    }
    return 0;
  }

  auto pmresult = pm.run();
  if (!pmresult) {
    std::cerr << pmresult.takeError() << "\n";
    return 2;
  } else if (!ast.diagnostics().ok()) {
    ast.diagnostics().emit(std::cerr);
    return 1;
  }

  // Emits warnings
  ast.diagnostics().emit(std::cout);

  if (args.build_mode == BuildMode::AHEAD_OF_TIME) {
    // Note: this should use the fully-linked version in the future, but
    // presently it is just using the single object.
    auto& out = pmresult->get<ast::BpfObject>();
    return aot::generate(
        bpftrace.resources, args.aot, out.data.data(), out.data.size());
  }

  if (args.mode == Mode::CODEGEN)
    return 0;

  auto c_definitions = pmresult->get<ast::CDefinitions>();
  auto& bytecode = pmresult->get<BpfBytecode>();
  return run_bpftrace(bpftrace,
                      args.output_file,
                      args.output_format,
                      c_definitions,
                      bytecode,
                      std::move(args.named_params),
                      args.obc);
}
