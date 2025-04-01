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
#include "ast/attachpoint_parser.h"
#include "ast/diagnostic.h"
#include "ast/helpers.h"
#include "ast/pass_manager.h"
#include "ast/passes/codegen_llvm.h"
#include "ast/passes/config_analyser.h"
#include "ast/passes/parser.h"
#include "ast/passes/pid_filter_pass.h"
#include "ast/passes/portability_analyser.h"
#include "ast/passes/printer.h"
#include "ast/passes/probe_analyser.h"
#include "ast/passes/recursion_check.h"
#include "ast/passes/resolve_imports.h"
#include "ast/passes/resource_analyser.h"
#include "ast/passes/return_path_analyser.h"
#include "ast/passes/semantic_analyser.h"
#include "bpffeature.h"
#include "bpftrace.h"
#include "btf.h"
#include "build_info.h"
#include "child.h"
#include "clang_parser.h"
#include "config.h"
#include "lockdown.h"
#include "log.h"
#include "output.h"
#include "probe_matcher.h"
#include "procmon.h"
#include "run_bpftrace.h"
#include "util/env.h"
#include "util/format.h"
#include "util/int_parser.h"
#include "util/kernel.h"
#include "version.h"

using namespace bpftrace;

namespace {
enum class OutputBufferConfig {
  UNSET = 0,
  LINE,
  FULL,
  NONE,
};

enum class TestMode {
  UNSET = 0,
  CODEGEN,
};

enum class BuildMode {
  // Compile script and run immediately
  DYNAMIC = 0,
  // Compile script into portable executable
  AHEAD_OF_TIME,
};

enum Options {
  INFO = 2000,
  NO_WARNING,
  TEST,
  AOT,
  HELP,
  VERSION,
  USDT_SEMAPHORE,
  UNSAFE,
  BTF,
  INCLUDE,
  EMIT_ELF,
  EMIT_LLVM,
  NO_FEATURE,
  DEBUG,
  DRY_RUN,
};
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
  out << "    -o file        redirect bpftrace output to file" << std::endl;
  out << "    -e 'program'   execute this program" << std::endl;
  out << "    -h, --help     show this help message" << std::endl;
  out << "    -I DIR         add the directory to the include search path" << std::endl;
  out << "    --include FILE add an #include file before preprocessing" << std::endl;
  out << "    -l [search|filename]" << std::endl;
  out << "                   list kernel probes or probes in a program" << std::endl;
  out << "    -p PID         filter actions and enable USDT probes on PID" << std::endl;
  out << "    -c 'CMD'       run CMD and enable USDT probes on resulting process" << std::endl;
  out << "    --usdt-file-activation" << std::endl;
  out << "                   activate usdt semaphores based on file path" << std::endl;
  out << "    --unsafe       allow unsafe/destructive functionality" << std::endl;
  out << "    -q             keep messages quiet" << std::endl;
  out << "    --info         Print information about kernel BPF support" << std::endl;
  out << "    -k             emit a warning when probe read helpers return an error" << std::endl;
  out << "    -V, --version  bpftrace version" << std::endl;
  out << "    --no-warnings  disable all warning messages" << std::endl;
  out << std::endl;
  out << "TROUBLESHOOTING OPTIONS:" << std::endl;
  out << "    -v                      verbose messages" << std::endl;
  out << "    --dry-run               terminate execution right after attaching all the probes" << std::endl;
  out << "    -d STAGE                debug info for various stages of bpftrace execution" << std::endl;
  out << "                            ('all', 'ast', 'codegen', 'codegen-opt', 'dis', 'libbpf', 'verifier')" << std::endl;
  out << "    --emit-elf FILE         (dry run) generate ELF file with bpf programs and write to FILE" << std::endl;
  out << "    --emit-llvm FILE        write LLVM IR to FILE.original.ll and FILE.optimized.ll" << std::endl;
  out << std::endl;
  out << "ENVIRONMENT:" << std::endl;
  out << "    BPFTRACE_BTF                      [default: none] BTF file" << std::endl;
  out << "    BPFTRACE_CACHE_USER_SYMBOLS       [default: auto] enable user symbol cache" << std::endl;
  out << "    BPFTRACE_COLOR                    [default: auto] enable log output colorization" << std::endl;
  out << "    BPFTRACE_CPP_DEMANGLE             [default: 1] enable C++ symbol demangling" << std::endl;
  out << "    BPFTRACE_DEBUG_OUTPUT             [default: 0] enable bpftrace's internal debugging outputs" << std::endl;
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

static void enforce_infinite_rlimit()
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

  std::cout << "System" << std::endl
            << "  OS: " << utsname.sysname << " " << utsname.release << " "
            << utsname.version << std::endl
            << "  Arch: " << utsname.machine << std::endl;

  std::cout << std::endl;
  std::cout << BuildInfo::report();

  std::cout << std::endl;
  std::cout << BPFfeature(no_feature).report();
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

static void parse_env(BPFtrace& bpftrace)
{
  ConfigSetter config_setter(*bpftrace.config_, ConfigSource::env_var);
  util::get_uint64_env_var("BPFTRACE_MAX_STRLEN", [&](uint64_t x) {
    config_setter.set(ConfigKeyInt::max_strlen, x);
  });

  util::get_uint64_env_var("BPFTRACE_STRLEN", [&](uint64_t x) {
    LOG(WARNING) << "BPFTRACE_STRLEN is deprecated. Use "
                    "BPFTRACE_MAX_STRLEN instead.";
    config_setter.set(ConfigKeyInt::max_strlen, x);
  });

  if (const char* env_p = std::getenv("BPFTRACE_STR_TRUNC_TRAILER"))
    config_setter.set(ConfigKeyString::str_trunc_trailer, std::string(env_p));

  util::get_bool_env_var("BPFTRACE_CPP_DEMANGLE", [&](bool x) {
    config_setter.set(ConfigKeyBool::cpp_demangle, x);
  });

  util::get_bool_env_var("BPFTRACE_DEBUG_OUTPUT",
                         [&](bool x) { bpftrace.debug_output_ = x; });

  util::get_bool_env_var("BPFTRACE_LAZY_SYMBOLICATION", [&](bool x) {
    config_setter.set(ConfigKeyBool::lazy_symbolication, x);
  });

  util::get_uint64_env_var("BPFTRACE_MAX_MAP_KEYS", [&](uint64_t x) {
    config_setter.set(ConfigKeyInt::max_map_keys, x);
  });

  util::get_uint64_env_var("BPFTRACE_MAX_PROBES", [&](uint64_t x) {
    config_setter.set(ConfigKeyInt::max_probes, x);
  });

  util::get_uint64_env_var("BPFTRACE_MAX_BPF_PROGS", [&](uint64_t x) {
    config_setter.set(ConfigKeyInt::max_bpf_progs, x);
  });

  util::get_uint64_env_var("BPFTRACE_LOG_SIZE", [&](uint64_t x) {
    config_setter.set(ConfigKeyInt::log_size, x);
  });

  util::get_uint64_env_var("BPFTRACE_PERF_RB_PAGES", [&](uint64_t x) {
    config_setter.set(ConfigKeyInt::perf_rb_pages, x);
  });

  util::get_uint64_env_var("BPFTRACE_MAX_CAT_BYTES", [&](uint64_t x) {
    config_setter.set(ConfigKeyInt::max_cat_bytes, x);
  });

  if (const char* env_p = std::getenv("BPFTRACE_CACHE_USER_SYMBOLS")) {
    const std::string s(env_p);
    if (!config_setter.set_user_symbol_cache_type(s))
      exit(1);
  }

  util::get_uint64_env_var("BPFTRACE_MAX_AST_NODES",
                           [&](uint64_t x) { bpftrace.max_ast_nodes_ = x; });

  if (const char* stack_mode = std::getenv("BPFTRACE_STACK_MODE")) {
    if (!config_setter.set_stack_mode(stack_mode))
      exit(1);
  }

  util::get_bool_env_var("BPFTRACE_NO_CPP_DEMANGLE", [&](bool x) {
    LOG(WARNING) << "BPFTRACE_NO_CPP_DEMANGLE is deprecated. Use "
                    "BPFTRACE_CPP_DEMANGLE=0 instead.";
    config_setter.set(ConfigKeyBool::cpp_demangle, !x);
  });

  util::get_uint64_env_var("BPFTRACE_CAT_BYTES_MAX", [&](uint64_t x) {
    LOG(WARNING) << "BPFTRACE_CAT_BYTES_MAX is deprecated. Use "
                    "BPFTRACE_MAX_CAT_BYTES instead.";
    config_setter.set(ConfigKeyInt::max_cat_bytes, x);
  });

  util::get_uint64_env_var("BPFTRACE_MAP_KEYS_MAX", [&](uint64_t x) {
    LOG(WARNING) << "BPFTRACE_MAP_KEYS_MAX is deprecated. Use "
                    "BPFTRACE_MAX_MAP_KEYS instead.";
    config_setter.set(ConfigKeyInt::max_map_keys, x);
  });

  util::get_bool_env_var("BPFTRACE_USE_BLAZESYM", [&](bool x) {
#ifndef HAVE_BLAZESYM
    if (x) {
      LOG(ERROR) << "BPFTRACE_USE_BLAZESYM requires blazesym support enabled "
                    "during build.";
      exit(1);
    }
#endif
    config_setter.set(ConfigKeyBool::use_blazesym, x);
  });
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
  bool found_kernel_headers = util::get_kernel_dirs(utsname, ksrc, kobj);

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

void CreateDynamicPasses(std::function<void(ast::Pass&& pass)> add)
{
  add(ast::CreateConfigPass());
  add(ast::CreateResolveImportsPass({}));
  add(ast::CreatePidFilterPass());
  add(ast::CreateSemanticPass());
  add(ast::CreateResourcePass());
  add(ast::CreateRecursionCheckPass());
  add(ast::CreateReturnPathPass());
  add(ast::CreateProbePass());
}

void CreateAotPasses(std::function<void(ast::Pass&& pass)> add)
{
  add(ast::CreateSemanticPass());
  add(ast::CreatePortabilityPass());
  add(ast::CreateResourcePass());
  add(ast::CreateRecursionCheckPass());
  add(ast::CreateReturnPathPass());
  add(ast::CreateProbePass());
}

ast::Pass printPass(const std::string& name)
{
  return ast::Pass::create("print-" + name, [=](ast::ASTContext& ast) {
    std::cerr << "AST after: " << name << std::endl;
    std::cerr << "-------------------" << std::endl;
    ast::Printer printer(std::cerr);
    printer.visit(ast.root);
    std::cerr << std::endl;
  });
};

struct Args {
  std::string pid_str;
  std::string cmd_str;
  bool listing = false;
  bool safe_mode = true;
  bool usdt_file_activation = false;
  int helper_check_level = 1;
  bool no_warnings = false;
  TestMode test_mode = TestMode::UNSET;
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
    option{ .name = "help",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::HELP },
    option{ .name = "version",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::VERSION },
    option{ .name = "usdt-file-activation",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::USDT_SEMAPHORE },
    option{ .name = "unsafe",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::UNSAFE },
    option{ .name = "btf",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::BTF },
    option{ .name = "include",
            .has_arg = required_argument,
            .flag = nullptr,
            .val = Options::INCLUDE },
    option{ .name = "info",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::INFO },
    option{ .name = "emit-llvm",
            .has_arg = required_argument,
            .flag = nullptr,
            .val = Options::EMIT_LLVM },
    option{ .name = "emit-elf",
            .has_arg = required_argument,
            .flag = nullptr,
            .val = Options::EMIT_ELF },
    option{ .name = "no-warnings",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::NO_WARNING },
    option{ .name = "test",
            .has_arg = required_argument,
            .flag = nullptr,
            .val = Options::TEST },
    option{ .name = "aot",
            .has_arg = required_argument,
            .flag = nullptr,
            .val = Options::AOT },
    option{ .name = "no-feature",
            .has_arg = required_argument,
            .flag = nullptr,
            .val = Options::NO_FEATURE },
    option{ .name = "debug",
            .has_arg = required_argument,
            .flag = nullptr,
            .val = Options::DEBUG },
    option{ .name = "dry-run",
            .has_arg = no_argument,
            .flag = nullptr,
            .val = Options::DRY_RUN },
    option{ .name = nullptr, .has_arg = 0, .flag = nullptr, .val = 0 }, // Must
                                                                        // be
                                                                        // last
  };

  int c;
  bool has_k = false;
  while ((c = getopt_long(argc, argv, short_options, long_options, nullptr)) !=
         -1) {
    switch (c) {
      case Options::INFO: // --info
        check_is_root();
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
        DISABLE_LOG(WARNING);
        args.no_warnings = true;
        args.helper_check_level = 0;
        break;
      case Options::TEST: // --test
        if (std::strcmp(optarg, "codegen") == 0)
          args.test_mode = TestMode::CODEGEN;
        else {
          LOG(ERROR) << "USAGE: --test can only be 'codegen'.";
          exit(1);
        }
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
      case 'o':
        args.output_file = optarg;
        break;
      case 'd':
      case Options::DEBUG:
        if (!parse_debug_stages(optarg))
          exit(1);
        break;
      case 'q':
        bt_quiet = true;
        break;
      case 'v':
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
        args.pid_str = optarg;
        break;
      case 'I':
        args.include_dirs.emplace_back(optarg);
        break;
      case Options::INCLUDE:
        args.include_files.emplace_back(optarg);
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
        usage(std::cout);
        exit(0);
      case 'V':
      case Options::VERSION:
        std::cout << "bpftrace " << BPFTRACE_VERSION << std::endl;
        exit(0);
      case 'k':
        if (has_k) {
          LOG(ERROR) << "USAGE: -kk has been deprecated. Use a single -k for "
                        "runtime warnings for errors in map "
                        "lookups and probe reads.";
          exit(1);
        }
        if (!args.no_warnings) {
          args.helper_check_level = 2;
        }
        has_k = true;
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
  if (args.helper_check_level == 2 &&
      args.build_mode == BuildMode::AHEAD_OF_TIME) {
    LOG(ERROR) << "Cannot use -k with --aot";
    exit(1);
  }

  if (args.listing) {
    // Expect zero or one positional arguments
    if (optind == argc) {
      args.search = "*:*";
    } else if (optind == argc - 1) {
      std::string val(argv[optind]);
      if (std::filesystem::exists(val)) {
        args.filename = val;
      } else {
        if (val == "*") {
          args.search = "*:*";
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

    // Load positional parameters before driver runs so positional
    // parameters used inside attach point definitions can be resolved.
    while (optind < argc) {
      args.params.emplace_back(argv[optind]);
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

static ast::ASTContext buildListProgram(const std::string& search)
{
  ast::ASTContext ast("listing", search);
  auto* ap = ast.make_node<ast::AttachPoint>(search, true, location());
  auto* probe = ast.make_node<ast::Probe>(
      ast::AttachPointList({ ap }), nullptr, nullptr, location());
  ast.root = ast.make_node<ast::Program>("",
                                         nullptr,
                                         ast::ImportList(),
                                         ast::MapDeclList(),
                                         ast::SubprogList(),
                                         ast::ProbeList({ probe }),
                                         location());
  return ast;
}

int main(int argc, char* argv[])
{
  Log::get().set_colorize(is_colorize());
  const Args args = parse_args(argc, argv);
  std::ostream* os = &std::cout;
  std::ofstream outputstream;
  if (!args.output_file.empty()) {
    outputstream.open(args.output_file);
    if (outputstream.fail()) {
      LOG(ERROR) << "Failed to open output file: \"" << args.output_file
                 << "\": " << strerror(errno);
      exit(1);
    }
    os = &outputstream;
  }

  std::unique_ptr<Output> output;
  if (args.output_format.empty() || args.output_format == "text") {
    output = std::make_unique<TextOutput>(*os);
  } else if (args.output_format == "json") {
    output = std::make_unique<JsonOutput>(*os);
  } else {
    LOG(ERROR) << "Invalid output format \"" << args.output_format << "\"\n"
               << "Valid formats: 'text', 'json'";
    exit(1);
  }

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
  BPFtrace bpftrace(std::move(output), args.no_feature, std::move(config));

  parse_env(bpftrace);

  bpftrace.usdt_file_activation_ = args.usdt_file_activation;
  bpftrace.safe_mode_ = args.safe_mode;
  bpftrace.helper_check_level_ = args.helper_check_level;
  bpftrace.boottime_ = get_boottime();
  bpftrace.delta_taitime_ = get_delta_taitime();

  if (!args.pid_str.empty()) {
    std::string errmsg;
    auto maybe_pid = util::parse_pid(args.pid_str, errmsg);
    if (!maybe_pid.has_value()) {
      LOG(ERROR) << "Failed to parse pid: " + errmsg;
      exit(1);
    }
    try {
      bpftrace.procmon_ = std::make_unique<ProcMon>(*maybe_pid);
    } catch (const std::exception& e) {
      LOG(ERROR) << e.what();
      exit(1);
    }
  }

  if (!args.cmd_str.empty()) {
    bpftrace.cmd_ = args.cmd_str;
    try {
      bpftrace.child_ = std::make_unique<ChildProc>(args.cmd_str);
    } catch (const std::runtime_error& e) {
      LOG(ERROR) << "Failed to fork child: " << e.what();
      exit(1);
    }
  }

  // This is our primary program AST context. Initially it is empty, i.e. there
  // is no filename set or source file. The way we set it up depends on the
  // mode of execution below, and we expect that it will be reinitialized.
  ast::ASTContext ast;

  // Listing probes when there is no program.
  if (args.listing && args.script.empty() && args.filename.empty()) {
    check_is_root();

    if (is_type_name(args.search)) {
      // Print structure definitions
      bpftrace.parse_btf({});
      bpftrace.probe_matcher_->list_structs(args.search);
      return 0;
    }

    if (args.search.find(".") != std::string::npos &&
        args.search.find_first_of(":*") == std::string::npos) {
      LOG(WARNING)
          << "It appears that \'" << args.search
          << "\' is a filename but the file does not exist. Treating \'"
          << args.search << "\' as a search pattern.";
    }

    // To list tracepoints, we construct a synthetic AST and then expand the
    // probe. The raw contents of the program are the initial search provided.
    ast = buildListProgram(args.search);

    // Parse and expand all the attachpoints. We don't need to descend into the
    // actual driver here, since we know that the program is already formed.
    auto ok = ast::PassManager()
                  .put(ast)
                  .put(bpftrace)
                  .add(ast::CreateParseAttachpointsPass(args.listing))
                  .add(CreateParseBTFPass())
                  .add(ast::CreateSemanticPass(args.listing))
                  .run();
    if (!ok || !ast.diagnostics().ok()) {
      ast.diagnostics().emit(std::cerr);
      return 1;
    }

    bpftrace.probe_matcher_->list_probes(ast.root);
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

  for (const auto& param : args.params) {
    bpftrace.add_param(param);
  }

  // If we are not running anything, then we don't require root.
  if (args.test_mode != TestMode::CODEGEN) {
    check_is_root();

    auto lockdown_state = lockdown::detect();
    if (lockdown_state == lockdown::LockdownState::Confidentiality) {
      lockdown::emit_warning(std::cerr);
      return 1;
    }

    // FIXME (mmarchini): maybe we don't want to always enforce an infinite
    // rlimit?
    enforce_infinite_rlimit();
  }

  // Temporarily, we make the full `BPFTrace` object available via the pass
  // manager (and objects are temporarily mutable). As passes are refactored
  // into lighter-weight components, the `BPFTrace` object should be decomposed
  // into its meaningful parts. Furthermore, the codegen and field analysis
  // passes will be rolled into the pass manager as regular passes; the final
  // binary is merely one of the outputs that can be extracted.
  ast::PassManager pm;
  pm.put(ast);
  pm.put(bpftrace);
  auto flags = extra_flags(bpftrace, args.include_dirs, args.include_files);

  if (args.listing) {
    pm.add(CreateParsePass())
        .add(ast::CreateParseAttachpointsPass(args.listing))
        .add(CreateParseBTFPass())
        .add(ast::CreateSemanticPass(args.listing));

    auto ok = pm.run();
    if (!ok || !ast.diagnostics().ok()) {
      ast.diagnostics().emit(std::cerr);
      return 1;
    }
    bpftrace.probe_matcher_->list_probes(ast.root);
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
  for (auto& pass : ast::AllParsePasses(std::move(flags))) {
    addPass(std::move(pass));
  }

  switch (args.build_mode) {
    case BuildMode::DYNAMIC:
      CreateDynamicPasses(addPass);
      break;
    case BuildMode::AHEAD_OF_TIME:
      CreateAotPasses(addPass);
      break;
  }

  pm.add(ast::CreateLLVMInitPass());
  pm.add(ast::CreateCompilePass());
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
  bool verify_llvm_ir = false;
  util::get_bool_env_var("BPFTRACE_VERIFY_LLVM_IR",
                         [&](bool x) { verify_llvm_ir = x; });
  if (verify_llvm_ir) {
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

  auto pmresult = pm.run();
  if (!pmresult || !ast.diagnostics().ok()) {
    // Emits errors and warnings
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

  if (args.test_mode == TestMode::CODEGEN)
    return 0;

  auto& bytecode = pmresult->get<BpfBytecode>();
  return run_bpftrace(bpftrace, bytecode);
}
