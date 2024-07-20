#pragma once

#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <unordered_map>
#include <utility>
#include <vector>

#include "ast/ast.h"
#include "attached_probe.h"
#include "bpfbytecode.h"
#include "bpffeature.h"
#include "bpfprogram.h"
#include "btf.h"
#include "child.h"
#include "config.h"
#include "dwarf_parser.h"
#include "output.h"
#include "pcap_writer.h"
#include "printf.h"
#include "probe_matcher.h"
#include "procmon.h"
#include "required_resources.h"
#include "struct.h"
#include "types.h"
#include "utils.h"

#include <bcc/bcc_syms.h>

namespace bpftrace {

const int timeout_ms = 100;

struct symbol {
  std::string name;
  uint64_t start;
  uint64_t size;
  uint64_t address;
};

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

enum class DebugStage { Ast, Codegen, CodegenOpt, Libbpf, Verifier };

class WildcardException : public std::exception {
public:
  WildcardException(const std::string &msg) : msg_(msg)
  {
  }

  const char *what() const noexcept override
  {
    return msg_.c_str();
  }

private:
  std::string msg_;
};

class BPFtrace {
public:
  BPFtrace(std::unique_ptr<Output> o = std::make_unique<TextOutput>(std::cout),
           BPFnofeature no_feature = BPFnofeature(),
           Config config = Config())
      : out_(std::move(o)),
        feature_(std::make_unique<BPFfeature>(no_feature)),
        probe_matcher_(std::make_unique<ProbeMatcher>(this)),
        ncpus_(get_possible_cpus().size()),
        config_(config)
  {
  }
  virtual ~BPFtrace();
  virtual int add_probe(const ast::AttachPoint &ap,
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
                        int pid,
                        int probe_id,
                        bool ustack,
                        StackType stack_type,
                        int indent = 0);
  std::string resolve_buf(char *buf, size_t size);
  std::string resolve_ksym(uint64_t addr, bool show_offset = false);
  std::string resolve_usym(uint64_t addr,
                           int pid,
                           int probe_id,
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
  uint64_t resolve_cgroupid(const std::string &path) const;
  std::vector<std::unique_ptr<IPrintable>> get_arg_values(
      const std::vector<Field> &args,
      uint8_t *arg_data);
  void add_param(const std::string &param);
  std::string get_param(size_t index, bool is_str) const;
  size_t num_params() const;
  void request_finalize();
  std::string get_string_literal(const ast::Expression *expr) const;
  std::optional<int64_t> get_int_literal(const ast::Expression *expr) const;
  std::optional<std::string> get_watchpoint_binary_path() const;
  virtual bool is_traceable_func(const std::string &func_name) const;
  virtual std::unordered_set<std::string> get_func_modules(
      const std::string &func_name) const;
  int create_pcaps(void);
  void close_pcaps(void);
  bool write_pcaps(uint64_t id, uint64_t ns, uint8_t *pkt, unsigned int size);

  void parse_btf(const std::set<std::string> &modules);
  bool has_btf_data() const;
  Dwarf *get_dwarf(const std::string &filename);
  Dwarf *get_dwarf(const ast::AttachPoint &attachpoint);
  void kfunc_recursion_check(ast::Program *prog);

  std::string cmd_;
  bool finalize_ = false;
  // Global variables checking if an exit/usr1 signal was received
  static volatile sig_atomic_t exitsig_recv;
  static volatile sig_atomic_t sigusr1_recv;

  RequiredResources resources;
  BpfBytecode bytecode_;
  StructManager structs;
  std::map<std::string, std::string> macros_;
  std::map<std::string, uint64_t> enums_;
  std::map<libbpf::bpf_func_id, location> helper_use_loc_;
  const FuncsModulesMap &get_traceable_funcs() const;
  KConfig kconfig;
  std::vector<std::unique_ptr<AttachedProbe>> attached_probes_;

  std::map<std::string, std::unique_ptr<PCAPwriter>> pcap_writers;

  unsigned int join_argnum_ = 16;
  unsigned int join_argsize_ = 1024;
  std::unique_ptr<Output> out_;
  std::unique_ptr<BPFfeature> feature_;

  bool resolve_user_symbols_ = true;
  bool safe_mode_ = true;
  bool has_usdt_ = false;
  bool usdt_file_activation_ = false;
  int helper_check_level_ = 0;
  uint64_t max_ast_nodes_ = 0; // Maximum AST nodes allowed for fuzzing
  bool debug_output_ = false;
  std::optional<struct timespec> boottime_;
  std::optional<struct timespec> delta_taitime_;
  static constexpr uint32_t event_loss_cnt_key_ = 0;
  static constexpr uint64_t event_loss_cnt_val_ = 0;
  bool need_recursion_check_ = false;

  static void sort_by_key(
      std::vector<SizedType> key_args,
      std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
          &values_by_key);

  std::unique_ptr<ProbeMatcher> probe_matcher_;

  std::unique_ptr<BTF> btf_;
  std::unordered_set<std::string> btf_set_;
  std::unique_ptr<ChildProcBase> child_;
  std::unique_ptr<ProcMonBase> procmon_;
  pid_t pid(void) const
  {
    return procmon_ ? procmon_->pid() : 0;
  }
  int ncpus_;
  int online_cpus_;
  Config config_;

private:
  int run_special_probe(std::string name,
                        BpfBytecode &bytecode,
                        void (*trigger)(void));
  void *ksyms_{ nullptr };
  // note: exe_sym_ is used when layout is same for all instances of program
  std::map<std::string, std::pair<int, void *>> exe_sym_; // exe -> (pid, cache)
  std::map<int, void *> pid_sym_;                         // pid -> cache
  std::map<std::string, std::map<uintptr_t, elf_symbol, std::greater<>>>
      symbol_table_cache_;
  std::vector<std::string> params_;

  std::vector<std::unique_ptr<void, void (*)(void *)>> open_perf_buffers_;

  std::vector<std::unique_ptr<AttachedProbe>> attach_usdt_probe(
      Probe &probe,
      const BpfProgram &program,
      int pid,
      bool file_activation);
  int setup_output();
  int setup_perf_events();
  void setup_ringbuf();
  int setup_event_loss();
  // when the ringbuf feature is available, enable ringbuf for built-ins like
  // printf, cat.
  bool is_ringbuf_enabled(void) const
  {
    return feature_->has_map_ringbuf();
  }
  // when the ringbuf feature is unavailable or built-in skboutput is used,
  // enable perf_event
  bool is_perf_event_enabled(void) const
  {
    return !feature_->has_map_ringbuf() || resources.needs_perf_event_map;
  }
  void teardown_output();
  void poll_output(bool drain = false);
  int poll_perf_events();
  void handle_event_loss();
  int print_map_hist(const BpfMap &map, uint32_t top, uint32_t div);
  static uint64_t read_address_from_output(std::string output);
  std::optional<std::vector<uint8_t>> find_empty_key(const BpfMap &map) const;
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
  mutable FuncsModulesMap traceable_funcs_;

  std::unordered_map<std::string, std::unique_ptr<Dwarf>> dwarves_;
};

} // namespace bpftrace
