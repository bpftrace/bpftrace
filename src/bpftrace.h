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
#include "types.h"

namespace bpftrace {

class BPFtrace
{
public:
  BPFtrace() : ncpus_(ebpf::get_possible_cpus().size()) { }
  virtual ~BPFtrace() { }
  virtual int add_probe(ast::Probe &p);
  int num_probes() const;
  int run();
  int print_maps();
  std::string get_stack(uint32_t stackid, bool ustack, int indent=0);
  std::string resolve_sym(uintptr_t addr, bool show_offset=false);
  std::string resolve_usym(uintptr_t addr) const;

  std::map<std::string, std::unique_ptr<IMap>> maps_;
  std::map<std::string, std::tuple<uint8_t *, uintptr_t>> sections_;
  std::map<std::string, std::map<std::string, int>> structs_;
  std::vector<std::tuple<std::string, std::vector<SizedType>>> printf_args_;
  std::unique_ptr<IMap> stackid_map_;
  std::unique_ptr<IMap> perf_event_map_;

  static void sort_by_key(std::vector<SizedType> key_args,
      std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> &values_by_key);

protected:
  virtual std::set<std::string> find_wildcard_matches(const std::string &prefix, const std::string &attach_point, const std::string &file_name);
  std::vector<Probe> probes_;
  std::vector<Probe> special_probes_;

private:
  std::vector<std::unique_ptr<AttachedProbe>> attached_probes_;
  std::vector<std::unique_ptr<AttachedProbe>> special_attached_probes_;
  KSyms ksyms_;
  int ncpus_;
  int online_cpus_;

  std::unique_ptr<AttachedProbe> attach_probe(Probe &probe);
  int setup_perf_events();
  void poll_perf_events(int epollfd, int timeout=-1);
  int print_map(IMap &map);
  int print_map_quantize(IMap &map);
  int print_quantize(const std::vector<uint64_t> &values) const;
  static uint64_t reduce_value(const std::vector<uint8_t> &value, int ncpus);
  static std::string quantize_index_label(int power);
  std::vector<uint8_t> find_empty_key(IMap &map, size_t size) const;
};

} // namespace bpftrace
