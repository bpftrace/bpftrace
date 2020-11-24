#pragma once

#include <istream>
#include <set>

#include "ast/visitors.h"
#include "bpftrace.h"

namespace bpftrace {

namespace ast {

class TracepointArgsVisitor : public Visitor
{
public:
  void visit(Builtin &builtin) override
  {
    Visitor::visit(builtin);

    if (builtin.ident == "args" && probe_->tp_args_structs_level == -1)
      probe_->tp_args_structs_level = 0;
  };
  void visit(FieldAccess &acc) override
  {
    Visitor::visit(acc);

    if (probe_->tp_args_structs_level >= 0)
      probe_->tp_args_structs_level++;
  };
  void visit(Probe &probe) override {
    probe_ = &probe;
    Visitor::visit(probe);
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

} // namespace bpftrace
