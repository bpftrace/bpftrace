#pragma once

#include <istream>
#include <set>

#include "ast/visitors.h"
#include "bpftrace.h"

namespace bpftrace {

namespace ast {

class TracepointArgsVisitor : public ASTVisitor
{
public:
  void visit(Builtin &builtin) override
  {
    if (builtin.ident == "args")
      probe_->need_tp_args_structs = true;
  };
  void visit(Probe &probe) override {
    probe_ = &probe;
    ASTVisitor::visit(probe);
  };

private:
  Probe *probe_;
};
} // namespace ast

class TracepointFormatParser
{
public:
  static bool parse(ast::Program *program, BPFtrace &bpftrace);
  static std::string get_struct_name(const std::string &category,
                                     const std::string &event_name);
  static std::string get_struct_name(const std::string &probe_id);

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

} // namespace bpftrace
