#pragma once

#include <bcc/bcc_syms.h>
#include <cstdint>
#include <iostream>
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
#include "ast/location.h"
#include "ast/pass_manager.h"
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
#include "output.h"
#include "pcap_writer.h"
#include "printf.h"
#include "probe_matcher.h"
#include "procmon.h"
#include "required_resources.h"
#include "struct.h"
#include "types.h"
#include "usyms.h"
#include "util/cpus.h"
#include "util/kernel.h"

namespace bpftrace {

using util::symbol;

const int timeout_ms = 100;

struct stack_key {
  int64_t stackid;
  uint32_t nr_stack_frames;
};

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
  Verifier
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
  BPFtrace(std::unique_ptr<Output> o = std::make_unique<TextOutput>(std::cout),
           BPFnofeature no_feature = BPFnofeature(),
           std::unique_ptr<Config> config = std::make_unique<Config>())
      : out_(std::move(o)),
        btf_(std::make_unique<BTF>(this)),
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
  virtual int add_probe(ast::ASTContext &ctx,
                        const ast::AttachPoint &ap,
                        const ast::Probe &p,
                        int usdt_location_idx = 0);
  Probe generateWatchpointSetupProbe(const ast::AttachPoint &ap,
                                     const ast::Probe &probe);
  int num_probes() const;
  int prerun() const;
  int run(BpfBytecode bytecode);
  std::vector<std::unique_ptr<AttachedProbe>> attach_probe(
      Probe &probe,
      const BpfBytecode &bytecode);
  int run_iter();
  int print_maps();
  int clear_map(const BpfMap &map);
  int zero_map(const BpfMap &map);
  int print_map(const BpfMap &map, uint32_t top, uint32_t div);
  std::string get_stack(int64_t stackid,
                        uint32_t nr_stack_frames,
                        int32_t pid,
                        int32_t probe_id,
                        bool ustack,
                        StackType stack_type,
                        int indent = 0);
  std::string resolve_buf(const char *buf, size_t size);
  std::string resolve_ksym(uint64_t addr, bool show_offset = false);
  std::string resolve_usym(uint64_t addr,
                           int32_t pid,
                           int32_t probe_id,
                           bool show_offset = false,
                           bool show_module = false);
  std::string resolve_inet(int af, const uint8_t *inet) const;
  std::string resolve_uid(uint64_t addr) const;
  std::string resolve_timestamp(uint32_t mode,
                                uint32_t strftime_id,
                                uint64_t nsecs);
  uint64_t resolve_kname(const std::string &name) const;
  virtual int resolve_uname(const std::string &name,
                            struct symbol *sym,
                            const std::string &path) const;
  std::string resolve_mac_address(const uint8_t *mac_addr) const;
  std::string resolve_cgroup_path(uint64_t cgroup_path_id,
                                  uint64_t cgroup_id) const;
  std::string resolve_probe(uint64_t probe_id) const;
  std::vector<std::unique_ptr<IPrintable>> get_arg_values(
      const std::vector<Field> &args,
      uint8_t *arg_data);
  void add_param(const std::string &param);
  std::string get_param(size_t index) const;
  size_t num_params() const;
  void request_finalize();
  std::optional<std::string> get_watchpoint_binary_path() const;
  virtual bool is_traceable_func(const std::string &func_name) const;
  virtual std::unordered_set<std::string> get_func_modules(
      const std::string &func_name) const;
  virtual std::unordered_set<std::string> get_raw_tracepoint_modules(
      const std::string &name) const;
  virtual const struct stat &get_pidns_self_stat() const;

  bool write_pcaps(uint64_t id, uint64_t ns, uint8_t *pkt, unsigned int size);

  void parse_module_btf(const std::set<std::string> &modules);
  bool has_btf_data() const;
  Dwarf *get_dwarf(const std::string &filename);
  Dwarf *get_dwarf(const ast::AttachPoint &attachpoint);
  std::set<std::string> list_modules(const ast::ASTContext &ctx);

  std::string cmd_;
  bool finalize_ = false;
  static int exit_code;
  // Global variables checking if an exit/usr1 signal was received
  static volatile sig_atomic_t exitsig_recv;
  static volatile sig_atomic_t sigusr1_recv;

  RequiredResources resources;
  BpfBytecode bytecode_;
  StructManager structs;
  FunctionRegistry functions;
  std::map<std::string, std::string> macros_;
  // Map of enum variant_name to (variant_value, enum_name).
  std::map<std::string, std::tuple<uint64_t, std::string>> enums_;
  // Map of enum_name to map of variant_value to variant_name.
  std::map<std::string, std::map<uint64_t, std::string>> enum_defs_;
  // For each helper, list of all generated call sites.
  std::map<libbpf::bpf_func_id, std::vector<HelperErrorInfo>> helper_use_loc_;
  const util::FuncsModulesMap &get_traceable_funcs() const;
  const util::FuncsModulesMap &get_raw_tracepoints() const;
  util::KConfig kconfig;
  std::vector<std::unique_ptr<AttachedProbe>> attached_probes_;
  std::optional<int> sigusr1_prog_fd_;

  unsigned int join_argnum_ = 16;
  unsigned int join_argsize_ = 1024;
  std::unique_ptr<Output> out_;
  std::unique_ptr<BTF> btf_;
  std::unique_ptr<BPFfeature> feature_;

  bool resolve_user_symbols_ = true;
  bool safe_mode_ = true;
  bool has_usdt_ = false;
  bool usdt_file_activation_ = false;
  int helper_check_level_ = 1;
  uint64_t max_ast_nodes_ = std::numeric_limits<uint64_t>::max();
  bool debug_output_ = false;
  std::optional<struct timespec> boottime_;
  std::optional<struct timespec> delta_taitime_;
  static constexpr uint32_t event_loss_cnt_key_ = 0;
  static constexpr uint64_t event_loss_cnt_val_ = 0;
  bool need_recursion_check_ = false;

  static void sort_by_key(
      const SizedType &key,
      std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
          &values_by_key);

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
  int online_cpus_;
  int max_cpu_id_;
  std::unique_ptr<Config> config_;

private:
  Ksyms ksyms_;
  Usyms usyms_;
  std::vector<std::string> params_;

  std::vector<std::unique_ptr<void, void (*)(void *)>> open_perf_buffers_;
  std::map<std::string, std::unique_ptr<PCAPwriter>> pcap_writers_;

  std::vector<std::unique_ptr<AttachedProbe>> attach_usdt_probe(
      Probe &probe,
      const BpfProgram &program,
      std::optional<int> pid,
      bool file_activation);
  int create_pcaps();
  void close_pcaps();
  int setup_output();
  int setup_perf_events();
  void setup_ringbuf();
  int setup_event_loss();
  // when the ringbuf feature is available, enable ringbuf for built-ins like
  // printf, cat.
  bool is_ringbuf_enabled() const
  {
    return feature_->has_map_ringbuf();
  }
  // when the ringbuf feature is unavailable or built-in skboutput is used,
  // enable perf_event
  bool is_perf_event_enabled() const
  {
    return !feature_->has_map_ringbuf() || resources.needs_perf_event_map;
  }
  void teardown_output();
  void poll_output(bool drain = false);
  int poll_perf_events();
  void handle_event_loss();
  int print_map_hist(const BpfMap &map, uint32_t top, uint32_t div);
  static uint64_t read_address_from_output(std::string output);
  struct bcc_symbol_option &get_symbol_opts();
  Probe generate_probe(const ast::AttachPoint &ap,
                       const ast::Probe &p,
                       int usdt_location_idx = 0);
  bool has_iter_ = false;
  int epollfd_ = -1;
  struct ring_buffer *ringbuf_ = nullptr;
  uint64_t event_loss_count_ = 0;

  // Mapping traceable functions to modules (or "vmlinux") they appear in.
  // Needs to be mutable to allow lazy loading of the mapping from const lookup
  // functions.
  mutable util::FuncsModulesMap traceable_funcs_;
  mutable util::FuncsModulesMap raw_tracepoints_;
  std::unordered_map<std::string, std::unique_ptr<Dwarf>> dwarves_;
};

} // namespace bpftrace
