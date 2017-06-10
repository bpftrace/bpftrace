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
  virtual ~BPFtrace() { }
  virtual int add_probe(ast::Probe &p);
  int start();
  void stop();
  int print_maps();

  std::map<std::string, std::unique_ptr<Map>> maps_;
  std::map<std::string, std::tuple<uint8_t *, uintptr_t>> sections_;

private:
  std::vector<Probe> probes_;
  std::vector<std::unique_ptr<AttachedProbe>> attached_probes_;

  int print_map(Map &map);
  int print_map_quantize(Map &map);
  int print_quantize(std::vector<uint64_t> values);
  std::string quantize_index_label(int power);
  std::vector<uint8_t> find_empty_key(Map &map, size_t size);
};

} // namespace bpftrace
