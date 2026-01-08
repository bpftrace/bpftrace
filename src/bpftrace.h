#pragma once

#include <bcc/bcc_syms.h>
#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string_view>
#include <sys/stat.h>
#include <unordered_map>
#include <utility>
#include <vector>

#include "ast/ast.h"
#include "ast/pass_manager.h"
#include "ast/passes/ap_probe_expansion.h"
#include "ast/passes/clang_parser.h"
#include "attached_probe.h"
#include "bpfbytecode.h"
#include "bpffeature.h"
#include "bpfprogram.h"
#include "btf.h"
#include "child.h"
#include "config.h"
#include "dwarf_parser.h"
#include "functions.h"
#include "ksyms.h"
#include "output/output.h"
#include "pcap_writer.h"
#include "probe_matcher.h"
#include "procmon.h"
#include "required_resources.h"
#include "struct.h"
#include "types.h"
#include "usyms.h"
#include "util/cpus.h"
#include "util/kernel.h"
#include "util/result.h"

namespace bpftrace {

using util::symbol;

const int timeout_ms = 100;

enum class DebugStage;

// globals
extern std::set<DebugStage> bt_debug;
extern bool bt_quiet;
extern bool bt_verbose;
extern bool dry_run;

enum class DebugStage {
  Parse,
  Ast,
  Codegen,
  CodegenOpt,
  Disassemble,
  Libbpf,
  Verifier,
  Types,
};

const std::unordered_map<std::string_view, DebugStage> debug_stages = {
  // clang-format off
  { "parse", DebugStage::Parse },
  { "ast", DebugStage::Ast },
  { "codegen", DebugStage::Codegen },
  { "codegen-opt", DebugStage::CodegenOpt },
#ifndef NDEBUG
  { "dis", DebugStage::Disassemble },
#endif
  { "libbpf", DebugStage::Libbpf },
  { "verifier", DebugStage::Verifier },
  { "types", DebugStage::Types },
  // clang-format on
};

class WildcardException : public std::exception {
public:
  WildcardException(std::string msg) : msg_(std::move(msg))
  {
  }

  const char *what() const noexcept override
  {
    return msg_.c_str();
  }

private:
  std::string msg_;
};

class BPFtrace : public ast::State<"bpftrace"> {
public:
  BPFtrace(BPFnofeature no_feature = BPFnofeature(),
           std::unique_ptr<Config> config = std::make_unique<Config>())
      : btf_(std::make_unique<BTF>(this)),
        feature_(std::make_unique<BPFfeature>(no_feature, *btf_)),
        probe_matcher_(std::make_unique<ProbeMatcher>(this)),
        ncpus_(util::get_possible_cpus().size()),
        max_cpu_id_(util::get_max_cpu_id()),
        config_(std::move(config)),
        ksyms_(*config_),
        usyms_(*config_)
  {
  }
  ~BPFtrace() override;
  virtual int add_probe(const ast::AttachPoint &ap,
                        const ast::Probe &p,
                        ast::ExpansionType expansion,
                        std::set<std::string> expanded_funcs);
  Probe generateWatchpointSetupProbe(const ast::AttachPoint &ap,
                                     const ast::Probe &probe);
  int num_probes() const;
  int prerun() const;
  int run(output::Output &out,
          const ast::CDefinitions &c_definitions,
          BpfBytecode bytecode);
  virtual Result<std::unique_ptr<AttachedProbe>> attach_probe(
      Probe &probe,
      const BpfBytecode &bytecode);
  int run_iter();
  std::string get_stack(uint64_t nr_stack_frames,
                        std::vector<uint64_t>&& raw_stack,
                        int32_t pid,
                        int32_t probe_id,
                        bool ustack,
                        StackType stack_type,
                        int indent = 0);
  std::string get_stack(uint64_t nr_stack_frames,
                        const std::vector<bpf_stack_build_id>& raw_stack);
  std::string resolve_ksym(uint64_t addr);
  std::string resolve_usym(uint64_t addr, int32_t pid, int32_t probe_id);
  std::string resolve_inet(int af, const char *inet) const;
  std::string resolve_uid(uint64_t addr) const;
  std::chrono::time_point<std::chrono::system_clock> resolve_timestamp(
      uint32_t mode,
      uint64_t nsecs);
  std::string format_timestamp(
      const std::chrono::time_point<std::chrono::system_clock> &time_point,
      uint32_t strftime_id);
  std::string format_timestamp(
      const std::chrono::time_point<std::chrono::system_clock> &time_point,
      const std::string &raw_fmt,
      bool utc);
  time_t time_since_epoch(uint32_t mode,
                          uint64_t timestamp_ns,
                          uint64_t *nsecs);
  uint64_t resolve_kname(const std::string &name) const;
  virtual int resolve_uname(const std::string &name,
                            struct symbol *sym,
                            const std::string &path) const;
  std::string resolve_mac_address(const char *mac_addr) const;
  std::string resolve_cgroup_path(uint64_t cgroup_path_id,
                                  uint64_t cgroup_id) const;
  std::string resolve_probe(uint64_t probe_id) const;
  void add_param(const std::string &param);
  std::string get_param(size_t index) const;
  size_t num_params() const;
  void request_finalize();
  std::optional<std::string> get_watchpoint_binary_path() const;
  virtual bool is_traceable_func(const std::string &func_name) const;
  virtual int resume_tracee(pid_t tracee_pid);
  virtual std::unordered_set<std::string> get_func_modules(
      const std::string &func_name) const;
  virtual std::unordered_set<std::string> get_raw_tracepoint_modules(
      const std::string &name) const;
  virtual const std::optional<struct stat> &get_pidns_self_stat() const;
  // This gets the number of perf or ring buffer pages in total across all cpus
  // by first checking if the user set this manually with a config value
  // (`perf_rb_pages`), then falling back to a dynamic default based on the
  // amount of available system memory
  virtual Result<uint64_t> get_buffer_pages(bool per_cpu = false) const;
  Result<uint64_t> get_buffer_pages_per_cpu() const;

  bool write_pcaps(uint64_t id, uint64_t ns, const OpaqueValue &pkt);
  void parse_module_btf(const std::set<std::string> &modules);
  bool has_btf_data() const;
  Dwarf *get_dwarf(const std::string &filename);
  Dwarf *get_dwarf(const ast::AttachPoint &attachpoint);
  std::set<std::string> list_modules(const ast::ASTContext &ctx);

  std::string cmd_;

  // Set by the async `exit` handler.
  bool finalize_ = false;
  int exit_code = 0;

  // Global variables checking if an exit/usr1 signal was received.
  static volatile sig_atomic_t exitsig_recv;
  static volatile sig_atomic_t sigusr1_recv;

  RequiredResources resources;
  BpfBytecode bytecode_;
  StructManager structs;
  FunctionRegistry functions;
  // For each helper, list of all generated call sites.
  std::map<bpf_func_id, std::vector<RuntimeErrorInfo>> helper_use_loc_;
  const util::FuncsModulesMap &get_traceable_funcs() const;
  const util::FuncsModulesMap &get_raw_tracepoints() const;
  util::KConfig kconfig;
  std::vector<std::unique_ptr<AttachedProbe>> attached_probes_;
  std::vector<int> sigusr1_prog_fds_;

  unsigned int join_argnum_ = 16;
  unsigned int join_argsize_ = 1024;
  std::unique_ptr<BTF> btf_;
  std::unique_ptr<BPFfeature> feature_;

  bool safe_mode_ = true;
  bool has_usdt_ = false;
  bool usdt_file_activation_ = false;
  int warning_level_ = 1;
  bool debug_output_ = false;
  std::optional<struct timespec> boottime_;
  std::optional<struct timespec> delta_taitime_;
  bool need_recursion_check_ = false;

  std::unique_ptr<ProbeMatcher> probe_matcher_;

  std::unordered_set<std::string> btf_set_;
  std::unique_ptr<ChildProcBase> child_;
  std::unique_ptr<ProcMonBase> procmon_;
  std::optional<pid_t> pid() const
  {
    if (procmon_) {
      return procmon_->pid();
    }
    return std::nullopt;
  }
  int ncpus_;
  int max_cpu_id_;
  std::unique_ptr<Config> config_;
  bool run_tests_ = false;
  bool run_benchmarks_ = false;

private:
  Ksyms ksyms_;
  Usyms usyms_;
  std::vector<std::string> params_;

  std::map<std::string, std::unique_ptr<PCAPwriter>> pcap_writers_;

  int create_pcaps();
  void close_pcaps();
  int setup_output(void *ctx);
  int setup_skboutput_perf_buffer(void *ctx);
  void setup_ringbuf(void *ctx);
  std::vector<std::string> resolve_ksym_stack(uint64_t addr,
                                              bool show_offset,
                                              bool perf_mode,
                                              bool show_debug_info);
  std::vector<std::string> resolve_usym_stack(uint64_t addr,
                                              int32_t pid,
                                              int32_t probe_id,
                                              bool show_offset,
                                              bool perf_mode,
                                              bool show_debug_info);
  void teardown_output();
  void poll_output(output::Output &out, bool drain = false);
  void poll_event_loss(output::Output &out);
  static uint64_t read_address_from_output(std::string output);
  struct bcc_symbol_option &get_symbol_opts();
  Probe generate_probe(const ast::AttachPoint &ap,
                       const ast::Probe &p,
                       ast::ExpansionType expansion,
                       std::set<std::string> expanded_funcs);
  bool has_iter_ = false;
  struct ring_buffer *ringbuf_ = nullptr;
  struct perf_buffer *skb_perfbuf_ = nullptr;
  uint64_t event_loss_count_ = 0;

  // Mapping traceable functions to modules (or "vmlinux") they appear in.
  // Needs to be mutable to allow lazy loading of the mapping from const lookup
  // functions.
  mutable util::FuncsModulesMap traceable_funcs_;
  mutable util::FuncsModulesMap raw_tracepoints_;
  std::unordered_map<std::string, std::unique_ptr<Dwarf>> dwarves_;
};

} // namespace bpftrace
