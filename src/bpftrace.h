#pragma once

#include <map>
#include <memory>
#include <vector>

#include "ast.h"
#include "map.h"
#include "types.h"

namespace ebpf {
namespace bpftrace {

class BPFtrace
{
public:
  virtual ~BPFtrace() { }
  virtual int add_probe(ast::Probe &p);
  int run();
  int print_maps();

  std::map<std::string, Type> map_val_;
  std::map<std::string, std::vector<Type>> map_args_;
  std::map<std::string, std::unique_ptr<Map>> maps_;
  std::map<std::string, std::tuple<uint8_t *, uintptr_t>> sections_;

private:
  std::vector<Probe> probes_;
};

} // namespace bpftrace
} // namespace ebpf
