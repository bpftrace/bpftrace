#pragma once

#include <map>
#include <memory>
#include <vector>

#include "ast.h"
#include "attached_probe.h"
#include "map.h"
#include "types.h"

namespace bpftrace {

class BPFtrace
{
public:
  explicit BPFtrace(const std::string &path) : bpftrace_path_(path) { }
  virtual ~BPFtrace() { }
  virtual int add_probe(ast::Probe &p);
  int start();
  void stop();
  int print_maps() const;
  std::string get_stack(uint32_t stackid, bool ustack, int indent=0) const;

  std::map<std::string, std::unique_ptr<Map>> maps_;
  std::map<std::string, std::tuple<uint8_t *, uintptr_t>> sections_;
  std::map<std::string, std::vector<SizedType>> format_strings_;
  std::unique_ptr<Map> stackid_map_;
  std::unique_ptr<Map> perf_event_map_;

private:
  std::string bpftrace_path_;
  std::vector<Probe> probes_;
  std::vector<Probe> special_probes_;
  std::vector<std::unique_ptr<AttachedProbe>> attached_probes_;
  std::vector<std::unique_ptr<AttachedProbe>> special_attached_probes_;

  std::unique_ptr<AttachedProbe> attach_probe(Probe &probe);
  int setup_perf_events();
  static void poll_perf_events(int epollfd, int timeout=-1);
  int print_map(Map &map) const;
  int print_map_quantize(Map &map) const;
  int print_quantize(std::vector<uint64_t> values) const;
  std::string quantize_index_label(int power) const;
  std::vector<uint8_t> find_empty_key(Map &map, size_t size) const;
};

} // namespace bpftrace
