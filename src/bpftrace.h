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
#include "bpffeature.h"
#include "btf.h"
#include "child.h"
#include "dwarf_parser.h"
#include "map.h"
#include "mapmanager.h"
#include "output.h"
#include "pcap_writer.h"
#include "printf.h"
#include "probe_matcher.h"
#include "procmon.h"
#include "required_resources.h"
#include "struct.h"
#include "types.h"
#include "utils.h"

namespace bpftrace {

const int timeout_ms = 100;

struct symbol
{
  std::string name;
  uint64_t start;
  uint64_t size;
  uint64_t address;
};

enum class DebugLevel;

// globals
extern DebugLevel bt_debug;
extern bool bt_quiet;
extern bool bt_verbose;
extern bool bt_verbose2;

enum class DebugLevel
{
  kNone,
  kDebug,
  kFullDebug
};

inline DebugLevel operator++(DebugLevel &level, int)
{
  switch (level)
  {
    case DebugLevel::kNone:
      level = DebugLevel::kDebug;
      break;
    case DebugLevel::kDebug:
      level = DebugLevel::kFullDebug;
      break;
    case DebugLevel::kFullDebug:
      // NOTE (mmarchini): should be handled by the caller
      level = DebugLevel::kNone;
      break;
    default:
      break;
  }
  return level;
}

class WildcardException : public std::exception
{
public:
  WildcardException(const std::string &msg) : msg_(msg) {}

  const char *what() const noexcept override
  {
    return msg_.c_str();
  }

private:
  std::string msg_;
};

using BpfBytecode = std::unordered_map<std::string, std::vector<uint8_t>>;

class BPFtrace
{
public:
  BPFtrace(std::unique_ptr<Output> o = std::make_unique<TextOutput>(std::cout))
      : traceable_funcs_(get_traceable_funcs()),
        out_(std::move(o)),
        feature_(std::make_unique<BPFfeature>()),
        probe_matcher_(std::make_unique<ProbeMatcher>(this)),
        ncpus_(get_possible_cpus().size())
  {
  }
  virtual ~BPFtrace();
  virtual int add_probe(ast::Probe &p);
  Probe generateWatchpointSetupProbe(const std::string &func,
                                     const ast::AttachPoint &ap,
                                     const ast::Probe &probe);
  int num_probes() const;
  int prerun() const;
  int run(BpfBytecode bytecode);
  std::vector<std::unique_ptr<AttachedProbe>> attach_probe(
      Probe &probe,
      BpfBytecode &bytecode);
  int run_iter();
  int print_maps();
  int clear_map(IMap &map);
  int zero_map(IMap &map);
  int print_map(IMap &map, uint32_t top, uint32_t div);
  std::string get_stack(int64_t stackid,
                        int pid,
                        int probe_id,
                        bool ustack,
                        StackType stack_type,
                        int indent = 0);
  std::string resolve_buf(char *buf, size_t size);
  std::string resolve_ksym(uintptr_t addr, bool show_offset=false);
  std::string resolve_usym(uintptr_t addr,
                           int pid,
                           int probe_id,
                           bool show_offset = false,
                           bool show_module = false);
  std::string resolve_inet(int af, const uint8_t* inet) const;
  std::string resolve_uid(uintptr_t addr) const;
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
  virtual std::string extract_func_symbols_from_path(const std::string &path) const;
  std::string resolve_probe(uint64_t probe_id) const;
  uint64_t resolve_cgroupid(const std::string &path) const;
  std::vector<std::unique_ptr<IPrintable>> get_arg_values(const std::vector<Field> &args, uint8_t* arg_data);
  void add_param(const std::string &param);
  std::string get_param(size_t index, bool is_str) const;
  size_t num_params() const;
  void request_finalize();
  bool is_aslr_enabled(int pid);
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

  std::string cmd_;
  bool finalize_ = false;
  // Global variables checking if an exit/usr1 signal was received
  static volatile sig_atomic_t exitsig_recv;
  static volatile sig_atomic_t sigusr1_recv;

  RequiredResources resources;
  MapManager maps;
  BpfBytecode bytecode_;
  StructManager structs;
  std::map<std::string, std::string> macros_;
  std::map<std::string, uint64_t> enums_;
  std::map<libbpf::bpf_func_id, location> helper_use_loc_;
  // mapping traceable functions to modules (or "vmlinux") that they appear in
  FuncsModulesMap traceable_funcs_;
  KConfig kconfig;
  std::vector<std::unique_ptr<AttachedProbe>> attached_probes_;

  std::map<std::string, std::unique_ptr<PCAPwriter>> pcap_writers;

  unsigned int join_argnum_ = 16;
  unsigned int join_argsize_ = 1024;
  std::unique_ptr<Output> out_;
  std::unique_ptr<BPFfeature> feature_;

  uint64_t strlen_ = 64;
  const char *str_trunc_trailer_ = "..";
  uint64_t mapmax_ = 4096;
  size_t cat_bytes_max_ = 10240;
  uint64_t max_probes_ = 512;
  uint64_t max_programs_ = 512;
  uint64_t log_size_ = 1000000;
  uint64_t perf_rb_pages_ = 64;
  uint64_t max_type_res_iterations = 0;
  bool demangle_cpp_symbols_ = true;
  bool resolve_user_symbols_ = true;
  enum class UserSymbolCacheType
  {
    per_pid,
    per_program,
    none,
  } user_symbol_cache_type_;
  bool safe_mode_ = true;
  bool has_usdt_ = false;
  bool usdt_file_activation_ = false;
  int helper_check_level_ = 0;
  uint64_t ast_max_nodes_ = 0; // Maximum AST nodes allowed for fuzzing
  std::optional<StackMode> stack_mode_;
  std::optional<struct timespec> boottime_;
  std::optional<struct timespec> delta_taitime_;
  static constexpr uint32_t rb_loss_cnt_key_ = 0;
  static constexpr uint64_t rb_loss_cnt_val_ = 0;

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

private:
  int run_special_probe(std::string name,
                        BpfBytecode &bytecode,
                        void (*trigger)(void));
  void* ksyms_{nullptr};
  // note: exe_sym_ is used when layout is same for all instances of program
  std::map<std::string, std::pair<int, void *>> exe_sym_; // exe -> (pid, cache)
  std::map<int, void *> pid_sym_;                         // pid -> cache
  std::map<std::string, std::map<uintptr_t, elf_symbol, std::greater<>>>
      symbol_table_cache_;
  std::vector<std::string> params_;

  std::vector<std::unique_ptr<void, void (*)(void *)>> open_perf_buffers_;

  std::vector<std::unique_ptr<AttachedProbe>> attach_usdt_probe(
      Probe &probe,
      std::tuple<uint8_t *, uintptr_t> func,
      int pid,
      bool file_activation);
  int setup_output();
  int setup_perf_events();
  int setup_ringbuf();
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
  void handle_ringbuf_loss();
  int print_map_hist(IMap &map, uint32_t top, uint32_t div);
  int print_map_stats(IMap &map, uint32_t top, uint32_t div);
  static uint64_t read_address_from_output(std::string output);
  std::vector<uint8_t> find_empty_key(IMap &map, size_t size) const;
  bool has_iter_ = false;
  int epollfd_ = -1;
  struct ring_buffer *ringbuf_ = nullptr;
  uint64_t ringbuf_loss_count_ = 0;

  std::unordered_map<std::string, std::unique_ptr<Dwarf>> dwarves_;
};

} // namespace bpftrace
