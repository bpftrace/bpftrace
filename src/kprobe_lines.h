#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace bpftrace {

class BPFtrace;

namespace ast {
class AttachPoint;
}

struct KprobeLineQuery {
  std::string probe_name;
  std::string source_file;
  std::string kernel_module;
  size_t requested_line = 0;
  size_t requested_col = 0;
  bool exact_attachable = false;
  std::vector<size_t> nearby;
};

KprobeLineQuery query_kprobe_lines(BPFtrace &bpftrace,
                                   const ast::AttachPoint &ap,
                                   size_t radius = 8);

} // namespace bpftrace
