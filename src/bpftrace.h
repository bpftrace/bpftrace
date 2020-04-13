#pragma once

#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <unordered_map>
#include <utility>
#include <vector>

#include "ast.h"
#include "attached_probe.h"
#include "btf.h"
#include "imap.h"
#include "output.h"
#include "printf.h"
#include "struct.h"
#include "types.h"
#include "utils.h"

namespace bpftrace {

struct symbol
{
  std::string name;
  uint64_t start;
  uint64_t size;
  uint64_t address;
};

class BpfOrc;
enum class DebugLevel;

// globals
extern DebugLevel bt_debug;
extern bool bt_verbose;

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

class BPFtrace
{
public:
  BPFtrace(std::unique_ptr<Output> o = std::make_unique<TextOutput>(std::cout)) : out_(std::move(o)),ncpus_(get_possible_cpus().size()) { }
  virtual ~BPFtrace();
  virtual int add_probe(ast::Probe &p);
  int num_probes() const;
  int run(std::unique_ptr<BpfOrc> bpforc);
  int print_maps();
  int clear_map(IMap &map);
  int zero_map(IMap &map);
  int print_map(IMap &map, uint32_t top, uint32_t div);
  inline int next_probe_id() {
    return next_probe_id_++;
  };
  inline void source(std::string filename, std::string source) {
    src_ = source;
    filename_ = filename;
  }
  inline const std::string &source() { return src_; }
  inline IMap &get_map_by_id(uint32_t id)
  {
    return *maps_[map_ids_[id]].get();
  };
  std::string get_stack(uint64_t stackidpid, bool ustack, StackType stack_type, int indent=0);
  std::string resolve_buf(char *buf, size_t size);
  std::string resolve_ksym(uintptr_t addr, bool show_offset=false);
  std::string resolve_usym(uintptr_t addr, int pid, bool show_offset=false, bool show_module=false);
  std::string resolve_inet(int af, const uint8_t* inet) const;
  std::string resolve_uid(uintptr_t addr) const;
  uint64_t resolve_kname(const std::string &name) const;
  virtual int resolve_uname(const std::string &name,
                            struct symbol *sym,
                            const std::string &path) const;
  std::string map_value_to_str(IMap &map, std::vector<uint8_t> value, uint32_t div);
  virtual std::string extract_func_symbols_from_path(const std::string &path) const;
  std::string resolve_probe(uint64_t probe_id) const;
  uint64_t resolve_cgroupid(const std::string &path) const;
  std::vector<std::unique_ptr<IPrintable>> get_arg_values(const std::vector<Field> &args, uint8_t* arg_data);
  void add_param(const std::string &param);
  std::string get_param(size_t index, bool is_str) const;
  size_t num_params() const;
  void request_finalize();
  void error(std::ostream &out, const location &l, const std::string &m);
  void warning(std::ostream &out, const location &l, const std::string &m);
  void log_with_location(std::string, std::ostream &, const location &, const std::string &);
  bool has_child_cmd() { return cmd_.size() != 0; }
  virtual pid_t child_pid() { return child_pid_; };
  int spawn_child();
  void kill_child();
  bool is_aslr_enabled(int pid);

  std::string cmd_;
  int pid_{0};
  bool finalize_ = false;
  // Global variable checking if an exit signal was received
  static volatile sig_atomic_t exitsig_recv;

  std::map<std::string, std::unique_ptr<IMap>> maps_;

  // Maps a map id back to the map identifier. See get_map_by_id()
  std::vector<std::string> map_ids_;

  std::map<std::string, Struct> structs_;
  std::map<std::string, std::string> macros_;
  std::map<std::string, uint64_t> enums_;
  std::vector<std::tuple<std::string, std::vector<Field>>> printf_args_;
  std::vector<std::tuple<std::string, std::vector<Field>>> system_args_;
  std::vector<std::string> join_args_;
  std::vector<std::string> time_args_;
  std::vector<std::tuple<std::string, std::vector<Field>>> cat_args_;
  std::unordered_map<StackType, std::unique_ptr<IMap>> stackid_maps_;
  std::unique_ptr<IMap> join_map_;
  std::unique_ptr<IMap> elapsed_map_;
  std::unique_ptr<IMap> perf_event_map_;
  std::vector<std::string> probe_ids_;
  unsigned int join_argnum_;
  unsigned int join_argsize_;
  std::unique_ptr<Output> out_;

  uint64_t strlen_ = 64;
  uint64_t mapmax_ = 4096;
  size_t cat_bytes_max_ = 10240;
  uint64_t max_probes_ = 512;
  uint64_t log_size_ = 409600;
  bool demangle_cpp_symbols_ = true;
  bool resolve_user_symbols_ = true;
  bool cache_user_symbols_ = true;
  bool safe_mode_ = true;
  bool force_btf_ = false;

  static void sort_by_key(
      std::vector<SizedType> key_args,
      std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
          &values_by_key);
  std::set<std::string> find_wildcard_matches(
      const ast::AttachPoint &attach_point) const;
  std::set<std::string> find_wildcard_matches(
      const std::string &prefix,
      const std::string &func,
      std::istream &symbol_stream) const;
  std::set<std::string> find_symbol_matches(
      const ast::AttachPoint &attach_point) const;
  virtual std::unique_ptr<std::istream> get_symbols_from_file(
      const std::string &path) const;
  virtual std::unique_ptr<std::istream> get_symbols_from_usdt(
      int pid,
      const std::string &target) const;
  const std::string get_source_line(unsigned int);

  BTF btf_;
  std::unordered_set<std::string> btf_set_;
  std::map<std::string, std::map<std::string, SizedType>> btf_ap_args_;

protected:
  std::vector<Probe> probes_;
  std::vector<Probe> special_probes_;

private:
  int run_special_probe(std::string name,
                        const BpfOrc &bpforc,
                        void (*trigger)(void));
  std::vector<std::unique_ptr<AttachedProbe>> attached_probes_;
  void* ksyms_{nullptr};
  std::map<std::string, std::pair<int, void *>> exe_sym_; // exe -> (pid, cache)
  int ncpus_;
  int online_cpus_;
  std::vector<std::string> params_;
  int next_probe_id_ = 0;

  pid_t child_pid_ = 0;
  bool child_running_ = false; // true when `CHILD_GO` has been sent (child
                               // execve)
  int child_start_pipe_ = -1;

  std::string src_;
  std::string filename_;

  std::unique_ptr<AttachedProbe> attach_probe(Probe &probe,
                                              const BpfOrc &bpforc);
  int setup_perf_events();
  void poll_perf_events(int epollfd, bool drain = false);
  int print_map_hist(IMap &map, uint32_t top, uint32_t div);
  int print_map_stats(IMap &map);
  template <typename T>
  static T reduce_value(const std::vector<uint8_t> &value, int nvalues);
  static int64_t min_value(const std::vector<uint8_t> &value, int nvalues);
  static uint64_t max_value(const std::vector<uint8_t> &value, int nvalues);
  static uint64_t read_address_from_output(std::string output);
  std::vector<uint8_t> find_empty_key(IMap &map, size_t size) const;
  static bool is_pid_alive(int pid);
};

} // namespace bpftrace
