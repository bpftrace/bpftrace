#pragma once

#include <istream>
#include <set>

#include "ast/pass_manager.h"
#include "ast/visitor.h"
#include "bpftrace.h"

namespace bpftrace {

class TracepointFormatParser {
public:
  static bool parse(ast::ASTContext &ctx, BPFtrace &bpftrace);
  static std::string get_struct_name(const std::string &category,
                                     const std::string &event_name);
  static std::string get_struct_name(const std::string &probe_id);
  static void clear_struct_list()
  {
    struct_list.clear();
  }

private:
  static std::string parse_field(const std::string &line,
                                 int *last_offset,
                                 BPFtrace &bpftrace);
  static std::string adjust_integer_types(const std::string &field_type,
                                          int size);
  static std::set<std::string> struct_list;

protected:
  static std::string get_tracepoint_struct(std::istream &format_file,
                                           const std::string &category,
                                           const std::string &event_name,
                                           BPFtrace &bpftrace);
};

ast::Pass CreateParseTracepointFormatPass();

} // namespace bpftrace
