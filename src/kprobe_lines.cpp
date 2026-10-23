#include "kprobe_lines.h"

#include "ast/ast.h"
#include "bpftrace.h"
#include "dwarf_parser.h"
#include "log.h"
#include "probe_types.h"
#include "symbols/kernel.h"

#include <algorithm>
#include <iostream>
#include <llvm/Support/Error.h>

namespace bpftrace {

KprobeLineQuery query_kprobe_lines(BPFtrace &bpftrace,
                                   const ast::AttachPoint &ap,
                                   size_t radius)
{
  std::string location;
  if (!ap.target.empty())
    location = ap.target + ":";
  location += ap.source_file + ":" + std::to_string(ap.line_num);
  if (ap.col_num != 0)
    location += ":" + std::to_string(ap.col_num);

  std::string probe_name;
  if (ap.user_provided_name)
    probe_name = *ap.user_provided_name + "=";
  probe_name += ap.provider + "@" + location;
  KprobeLineQuery query{ .probe_name = probe_name,
                         .location = location,
                         .source_file = ap.source_file,
                         .kernel_module = ap.target,
                         .requested_line = ap.line_num,
                         .requested_col = ap.col_num };

  if (probetype(ap.provider) != ProbeType::kprobe) {
    query.error = "--list-kprobe-lines only supports kprobe source locations";
    return query;
  }

  Dwarf *dwarf = bpftrace.get_kernel_dwarf();
  if (dwarf == nullptr) {
    if (symbols::kernel_symbol_addresses_hidden()) {
      query.error =
          "Permission denied reading live kernel symbols; run as root or "
          "adjust kernel.kptr_restrict";
    } else {
      query.error =
          "No kernel DWARF debug info available; install matching kernel debug "
          "info or use --debuginfo";
    }
    return query;
  }

  auto exact = dwarf->line_to_addr(
      ap.source_file, ap.line_num, ap.col_num, ap.target);
  if (exact) {
    query.exact_attachable = true;
    query.function_info = dwarf->get_function_info(
        ap.source_file, ap.line_num, ap.col_num, ap.target);
    if (query.function_info && !query.function_info->name.empty() &&
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

static void print_source_function(const DwarfFunctionInfo &info,
                                  const std::string &indent)
{
  if (info.inline_function) {
    std::cout << indent << "function: " << info.inline_function->name << "\n"
              << indent << "kind: inline\n";
    if (!info.inline_function->declaration_file.empty() &&
        info.inline_function->declaration_line != 0)
      std::cout << indent
                << "declared_at: " << info.inline_function->declaration_file
                << ":" << info.inline_function->declaration_line << "\n";
    if (!info.inline_function->call_file.empty() &&
        info.inline_function->call_line != 0)
      std::cout << indent << "inlined_at: " << info.inline_function->call_file
                << ":" << info.inline_function->call_line << "\n";
    return;
  }

  std::cout << indent << "function: " << info.name << "\n"
            << indent << "kind: physical\n";
  if (!info.declaration_file.empty() && info.declaration_line != 0)
    std::cout << indent << "declared_at: " << info.declaration_file << ":"
              << info.declaration_line << "\n";
}

int list_kprobe_lines(BPFtrace &bpftrace, ast::ASTContext &ast)
{
  std::vector<KprobeLineQuery> results;
  for (auto *probe : ast.root->probes) {
    for (auto *ap : probe->attach_points) {
      if (probetype(ap->provider) != ProbeType::kprobe ||
          ap->source_file.empty() || ap->line_num == 0)
        continue;

      auto query = query_kprobe_lines(bpftrace, *ap);
      const auto duplicate = std::ranges::find_if(
          results, [&](const auto &existing) {
            return existing.kernel_module == query.kernel_module &&
                   existing.source_file == query.source_file &&
                   existing.requested_line == query.requested_line &&
                   existing.requested_col == query.requested_col;
          });
      if (duplicate == results.end())
        results.push_back(std::move(query));
    }
  }

  if (results.empty()) {
    LOG(ERROR) << "--list-kprobe-lines requires a source-location probe, e.g. "
                  "-e 'kprobe@fs/open.c:1428 { }'";
    return 1;
  }

  for (const auto &query : results) {
    std::cout << query.probe_name << "\n"
              << "  location: " << query.location << "\n"
              << "  status: "
              << (query.exact_attachable ? "MAPPED" : "NOT_MAPPED")
              << "\n  static_only: true\n";
    if (query.function && query.function_offset) {
      std::cout << "  function: " << *query.function << "+"
                << *query.function_offset << "\n";
    }
    if (query.function_info) {
      std::cout << "  source_function:\n";
      print_source_function(*query.function_info, "    ");
    }
    if (!query.exact_attachable) {
      if (!query.error.empty())
        std::cout << "  reason: " << query.error << "\n";
      else
        std::cout
            << "  reason: no instruction mapped by DWARF for requested line\n";
      if (query.nearby.empty()) {
        std::cout << "  nearby mapped lines: none within range\n";
      } else {
        std::cout << "  nearby mapped lines:\n";
        for (const auto line : query.nearby)
          std::cout << "    " << query.source_file << ":" << line << "\n";
      }
    }
  }

  for (const auto &query : results)
    if (!query.error.empty())
      return 1;
  return 0;
}

} // namespace bpftrace
