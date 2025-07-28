#pragma once

#include "ast/async_event_types.h"
#include "bpftrace.h"
#include "output/output.h"

namespace bpftrace::async_action {

enum class AsyncAction {
  // clang-format off
  printf          = 0,     // printf reserves 0-9999 for printf_ids
  printf_end      = 9999,
  syscall         = 10000, // system reserves 10000-19999 for printf_ids
  syscall_end     = 19999,
  cat             = 20000, // cat reserves 20000-29999 for printf_ids
  cat_end         = 29999,
  print_error     = 30000, // print_error reserves 20000-29999 for printf_ids
  print_error_end = 39999,
  exit            = 40000,
  print,
  clear,
  zero,
  time,
  join,
  runtime_error,
  print_non_map,
  strftime,
  watchpoint_attach,
  watchpoint_detach,
  skboutput,
  // clang-format on
};

class AsyncHandlers {
public:
  const static size_t MAX_TIME_STR_LEN = 64;

  AsyncHandlers(BPFtrace &bpftrace,
                const ast::CDefinitions &c_definitions,
                output::Output &output)
      : bpftrace(bpftrace), c_definitions(c_definitions), out(output) {};

  void exit(const OpaqueValue &data);
  void join(const OpaqueValue &data);
  void time(const OpaqueValue &data);
  void runtime_error(const OpaqueValue &data);
  void print_non_map(const OpaqueValue &data);
  void print_map(const OpaqueValue &data);
  void zero_map(const OpaqueValue &data);
  void clear_map(const OpaqueValue &data);
  void watchpoint_attach(const OpaqueValue &data);
  void watchpoint_detach(const OpaqueValue &data);
  void skboutput(const OpaqueValue &data);
  void syscall(const OpaqueValue &data);
  void cat(const OpaqueValue &data);
  void printf(const OpaqueValue &data);
  void print_error(const OpaqueValue &data);

private:
  BPFtrace &bpftrace;
  const ast::CDefinitions &c_definitions;
  output::Output &out;
};

} // namespace bpftrace::async_action
