#pragma once

#include <map>
#include <memory>
#include <set>
#include <vector>

#include "common.h"
#include "syms.h"

#include "ast.h"
#include "attached_probe.h"
#include "imap.h"
#include "struct.h"
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
  }
  return level;
}

class BPFtrace
{
public:
  BPFtrace() : ncpus_(ebpf::get_possible_cpus().size()) { }
  virtual ~BPFtrace() { }
  virtual int add_probe(ast::Probe &p);
  int num_probes() const;
  int run(std::unique_ptr<BpfOrc> bpforc);
  int print_maps();
  int print_map_ident(const std::string &ident, uint32_t top, uint32_t div);
  int clear_map_ident(const std::string &ident);
  int zero_map_ident(const std::string &ident);
  std::string get_stack(uint64_t stackidpid, bool ustack, int indent=0);
  std::string resolve_sym(uintptr_t addr, bool show_offset=false);
  std::string resolve_usym(uintptr_t addr, int pid, bool show_offset=false);
  std::string resolve_inet(int af, uint64_t inet);
  std::string resolve_uid(uintptr_t addr);
  uint64_t resolve_kname(const std::string &name);
  uint64_t resolve_uname(const std::string &name, const std::string &path);
  std::string resolve_probe(uint64_t probe_id);
  uint64_t resolve_cgroupid(const std::string &path);
  std::vector<uint64_t> get_arg_values(std::vector<Field> args, uint8_t* arg_data);
  int pid_;

  std::map<std::string, std::unique_ptr<IMap>> maps_;
  std::map<std::string, Struct> structs_;
  std::vector<std::tuple<std::string, std::vector<Field>>> printf_args_;
  std::vector<std::tuple<std::string, std::vector<Field>>> system_args_;
  std::vector<std::string> time_args_;
  std::unique_ptr<IMap> stackid_map_;
  std::unique_ptr<IMap> join_map_;
  std::unique_ptr<IMap> perf_event_map_;
  std::vector<std::string> probe_ids_;
  int join_argnum_;
  int join_argsize_;

  static void sort_by_key(std::vector<SizedType> key_args,
      std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> &values_by_key);
  virtual std::set<std::string> find_wildcard_matches(const std::string &prefix, const std::string &attach_point, const std::string &file_name);

protected:
  std::vector<Probe> probes_;
  std::vector<Probe> special_probes_;

private:
  std::vector<std::unique_ptr<AttachedProbe>> attached_probes_;
  std::vector<std::unique_ptr<AttachedProbe>> special_attached_probes_;
  KSyms ksyms_;
  std::map<int, void *> pid_sym_;
  int ncpus_;
  int online_cpus_;

  std::unique_ptr<AttachedProbe> attach_probe(Probe &probe, const BpfOrc &bpforc);
  int setup_perf_events();
  void poll_perf_events(int epollfd, int timeout=-1);
  int clear_map(IMap &map);
  int zero_map(IMap &map);
  int print_map(IMap &map, uint32_t top, uint32_t div);
  int print_map_hist(IMap &map, uint32_t top, uint32_t div);
  int print_map_lhist(IMap &map);
  int print_map_stats(IMap &map);
  int print_hist(const std::vector<uint64_t> &values, uint32_t div) const;
  int print_lhist(const std::vector<uint64_t> &values, int min, int max, int step) const;
  static uint64_t reduce_value(const std::vector<uint8_t> &value, int ncpus);
  static uint64_t min_value(const std::vector<uint8_t> &value, int ncpus);
  static uint64_t max_value(const std::vector<uint8_t> &value, int ncpus);
  static uint64_t read_address_from_output(std::string output);
  static std::string exec_system(const char* cmd);
  static std::string hist_index_label(int power);
  static std::string lhist_index_label(int number);
  static std::vector<std::string> split_string(std::string &str, char split_by);
  std::vector<uint8_t> find_empty_key(IMap &map, size_t size) const;
};

} // namespace bpftrace
