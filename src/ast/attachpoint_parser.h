#pragma once

#include <ostream>
#include <sstream>
#include <vector>

#include "ast.h"
#include "bpftrace.h"

namespace bpftrace {
namespace ast {

class AttachPointParser
{
public:
  AttachPointParser(Program *root,
                    BPFtrace &bpftrace,
                    std::ostream &sink,
                    bool listing);
  ~AttachPointParser() = default;
  int parse();

private:
  enum State
  {
    OK = 0,
    INVALID,
    NEW_APS,
    SKIP
  };

  State parse_attachpoint(AttachPoint &ap);
  /*
   * This method splits an attach point definition into arguments,
   * where arguments are separated by `:`. The exception is `:`s inside
   * of quoted strings, which we must treat as a literal.
   *
   * This method also resolves positional parameters. Positional params
   * may be escaped with double quotes.
   *
   * Note that this function assumes the raw string is generally well
   * formed. More specifically, that there is no unescaped whitespace
   * and no unmatched quotes.
   */
  State lex_attachpoint(const AttachPoint &ap);

  State kprobe_parser(bool allow_offset = true);
  State kretprobe_parser();
  State uprobe_parser(bool allow_offset = true, bool allow_abs_addr = true);
  State uretprobe_parser();
  State usdt_parser();
  State tracepoint_parser();
  State profile_parser();
  State interval_parser();
  State software_parser();
  State hardware_parser();
  State watchpoint_parser(bool async = false);
  State kfunc_parser();
  State iter_parser();

  std::optional<uint64_t> stoull(const std::string &str);

  Program *root_{ nullptr }; // Non-owning pointer
  BPFtrace &bpftrace_;
  std::ostream &sink_;
  AttachPoint *ap_{ nullptr }; // Non-owning pointer
  std::stringstream errs_;
  std::vector<std::string> parts_;
  AttachPointList new_attach_points;
  bool listing_;
};

} // namespace ast
} // namespace bpftrace
