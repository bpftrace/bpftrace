#include "kprobe_lines.h"

#include "ast/ast.h"
#include "bpftrace.h"
#include "dwarf_parser.h"

#include <llvm/Support/Error.h>

namespace bpftrace {

KprobeLineQuery query_kprobe_lines(BPFtrace &bpftrace,
                                   const ast::AttachPoint &ap,
                                   size_t radius)
{
  KprobeLineQuery query{ .probe_name = ap.raw_input,
                         .source_file = ap.source_file,
                         .kernel_module = ap.target,
                         .requested_line = ap.line_num,
                         .requested_col = ap.col_num };

  Dwarf *dwarf = bpftrace.get_kernel_dwarf();
  if (dwarf == nullptr)
    return query;

  auto exact = dwarf->line_to_addr(
      ap.source_file, ap.line_num, ap.col_num, ap.target);
  if (exact) {
    query.exact_attachable = true;
    return query;
  }
  llvm::consumeError(exact.takeError());

  query.nearby = dwarf->mapped_lines_near(
      ap.source_file, ap.line_num, radius, ap.target);
  return query;
}

} // namespace bpftrace
