#pragma once

#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <vector>
#include <unordered_map>

#include "ast.h"
#include "attached_probe.h"
#include "imap.h"
#include "printf.h"
#include "struct.h"
#include "utils.h"
#include "types.h"

namespace bpftrace {

class BpfOrc;
enum class DebugLevel;

// globals
extern DebugLevel bt_debug;
extern bool bt_verbose;

enum class DebugLevel {
  kNone,
  kDebug,
  kFullDebug
};

inline DebugLevel operator++(DebugLevel& level, int)
{
  switch (level) {
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
  BPFtrace(std::ostream& o = std::cout) : out_(o),ncpus_(get_possible_cpus().size()) { }
  virtual ~BPFtrace();
  virtual int add_probe(ast::Probe &p);
  int num_probes() const;
  std::ostream& outputstream() const { return out_; }
  int run(std::unique_ptr<BpfOrc> bpforc);
  int print_maps();
  int print_map_ident(const std::string &ident, uint32_t top, uint32_t div);
  int clear_map_ident(const std::string &ident);
  int zero_map_ident(const std::string &ident);
  inline int next_probe_id() {
    return next_probe_id_++;
  };
  std::string get_stack(uint64_t stackidpid, bool ustack, StackType stack_type, int indent=0);
  std::string resolve_ksym(uintptr_t addr, bool show_offset=false);
  std::string resolve_usym(uintptr_t addr, int pid, bool show_offset=false, bool show_module=false);
  std::string resolve_inet(int af, const uint8_t* inet) const;
  std::string resolve_uid(uintptr_t addr) const;
  uint64_t resolve_kname(const std::string &name) const;
  uint64_t resolve_uname(const std::string &name, const std::string &path) const;
  virtual std::string extract_func_symbols_from_path(const std::string &path) const;
  std::string resolve_probe(uint64_t probe_id) const;
  uint64_t resolve_cgroupid(const std::string &path) const;
  std::vector<std::unique_ptr<IPrintable>> get_arg_values(const std::vector<Field> &args, uint8_t* arg_data);
  void add_param(const std::string &param);
  bool is_numeric(std::string str) const;
  std::string get_param(size_t index) const;
  size_t num_params() const;
  void request_finalize();
  std::string cmd_;
  int pid_{0};
  bool finalize_ = false;

  std::map<std::string, std::unique_ptr<IMap>> maps_;
  std::map<std::string, Struct> structs_;
  std::map<std::string, std::string> macros_;
  std::map<std::string, uint64_t> enums_;
  std::vector<std::tuple<std::string, std::vector<Field>>> printf_args_;
  std::vector<std::tuple<std::string, std::vector<Field>>> system_args_;
  std::vector<std::string> join_args_;
  std::vector<std::string> time_args_;
  std::vector<std::string> cat_args_;
  std::unordered_map<StackType, std::unique_ptr<IMap>> stackid_maps_;
  std::unique_ptr<IMap> join_map_;
  std::unique_ptr<IMap> printf_map_;
  void *print_map_zero_;
  std::unique_ptr<IMap> perf_event_map_;
  std::vector<std::string> probe_ids_;
  unsigned int join_argnum_;
  unsigned int join_argsize_;

  uint64_t strlen_ = 64;
  uint64_t mapmax_ = 4096;
  size_t cat_bytes_max_ = 10240;
  uint64_t max_probes_ = 512;
  bool demangle_cpp_symbols = true;
  bool safe_mode = true;

  static void sort_by_key(
      std::vector<SizedType> key_args,
      std::vector<std::pair<std::vector<uint8_t>,
      std::vector<uint8_t>>> &values_by_key);
  std::set<std::string> find_wildcard_matches(
      const ast::AttachPoint &attach_point) const;
  std::set<std::string> find_wildcard_matches(
      const std::string &prefix,
      const std::string &func,
      std::istream &symbol_stream) const;
  virtual std::unique_ptr<std::istream> get_symbols_from_file(const std::string &path) const;
  virtual std::unique_ptr<std::istream> get_symbols_from_usdt(
      int pid,
      const std::string &target) const;

protected:
  std::vector<Probe> probes_;
  std::vector<Probe> special_probes_;

private:
  std::ostream &out_;
  std::vector<std::unique_ptr<AttachedProbe>> attached_probes_;
  std::vector<std::unique_ptr<AttachedProbe>> special_attached_probes_;
  void* ksyms_{nullptr};
  std::map<int, void *> pid_sym_;
  int ncpus_;
  int online_cpus_;
  std::vector<int> child_pids_;
  std::vector<std::string> params_;
  int next_probe_id_ = 0;

  std::unique_ptr<AttachedProbe> attach_probe(Probe &probe, const BpfOrc &bpforc);
  int setup_perf_events();
  void poll_perf_events(int epollfd, bool drain=false);
  int clear_map(IMap &map);
  int zero_map(IMap &map);
  int print_map(IMap &map, uint32_t top, uint32_t div);
  int print_map_hist(IMap &map, uint32_t top, uint32_t div);
  int print_map_lhist(IMap &map);
  int print_map_stats(IMap &map);
  int print_hist(const std::vector<uint64_t> &values, uint32_t div) const;
  int print_lhist(const std::vector<uint64_t> &values, int min, int max, int step) const;
  static uint64_t reduce_value(const std::vector<uint8_t> &value, int ncpus);
  static int64_t min_value(const std::vector<uint8_t> &value, int ncpus);
  static uint64_t max_value(const std::vector<uint8_t> &value, int ncpus);
  static uint64_t read_address_from_output(std::string output);
  static std::string hist_index_label(int power);
  static std::string lhist_index_label(int number);
  std::vector<uint8_t> find_empty_key(IMap &map, size_t size) const;
  static int spawn_child(const std::vector<std::string>& args, int *notify_trace_start_pipe_fd);
  static bool is_pid_alive(int pid);
};

} // namespace bpftrace
