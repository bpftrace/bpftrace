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
  if (dwarf == nullptr) {
    query.error =
        "No kernel DWARF debug info available; set BPFTRACE_VMLINUX or "
        "--debuginfo";
    return query;
  }

  auto exact = dwarf->line_to_addr(
      ap.source_file, ap.line_num, ap.col_num, ap.target);
  if (exact) {
    query.exact_attachable = true;
    query.function_info = dwarf->get_function_info(
        ap.source_file, ap.line_num, ap.col_num, ap.target);
    if (!exact->symbol.empty()) {
      query.function = exact->symbol;
      query.function_offset = exact->symbol_offset;
    } else if (query.function_info && !query.function_info->name.empty() &&
               query.function_info->low_pc &&
               exact->address >= *query.function_info->low_pc) {
      query.function = query.function_info->name;
      query.function_offset = exact->address - *query.function_info->low_pc;
    }
    return query;
  }
  DwarfParseError::Kind error_kind = DwarfParseError::Kind::Generic;
  std::string error_message;
  auto unhandled = llvm::handleErrors(exact.takeError(),
                                      [&](const DwarfParseError &error) {
                                        error_kind = error.kind();
                                        error_message = error.msg();
                                      });
  if (unhandled)
    error_message = llvm::toString(std::move(unhandled));

  if (error_kind == DwarfParseError::Kind::LineNotMapped) {
    query.nearby = dwarf->mapped_lines_near(
        ap.source_file, ap.line_num, radius, ap.target);
  } else {
    query.error = std::move(error_message);
  }
  return query;
}

} // namespace bpftrace
