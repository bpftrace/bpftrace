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
  AttachPointParser(Program *root, BPFtrace &bpftrace, std::ostream &sink);
  ~AttachPointParser() = default;
  int parse();

private:
  int parse_attachpoint(AttachPoint &ap);
  /*
   * This method splits an attach point definition into arguments,
   * where arguments are separated by `:`. The exception is `:`s inside
   * of quoted strings, which we must treat as a literal.
   *
   * Note that this function assumes the raw string is generally well
   * formed. More specifically, that there is no unescaped whitespace
   * and no unmatched quotes.
   */
  int lex_attachpoint(const std::string &raw);

  int kprobe_parser(bool allow_offset = true);
  int kretprobe_parser();
  int uprobe_parser(bool allow_offset = true, bool allow_abs_addr = true);
  int uretprobe_parser();
  int usdt_parser();
  int tracepoint_parser();
  int profile_parser();
  int interval_parser();
  int software_parser();
  int hardware_parser();
  int watchpoint_parser();
  int kfunc_parser();

  Program *root_{ nullptr }; // Non-owning pointer
  BPFtrace &bpftrace_;
  std::ostream &sink_;
  AttachPoint *ap_{ nullptr }; // Non-owning pointer
  std::stringstream errs_;
  std::vector<std::string> parts_;
};

} // namespace ast
} // namespace bpftrace
