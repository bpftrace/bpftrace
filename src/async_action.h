#pragma once

#include "ast/async_event_types.h"
#include "bpftrace.h"
#include "output/output.h"

namespace bpftrace::async_action {

enum class AsyncAction {
  // clang-format off
  printf      = 0,     // printf reserves 0-9999 for printf_ids
  printf_end  = 9999,
  syscall     = 10000, // system reserves 10000-19999 for printf_ids
  syscall_end = 19999,
  cat         = 20000, // cat reserves 20000-29999 for printf_ids
  cat_end     = 29999,
  exit        = 30000,
  print,
  clear,
  zero,
  time,
  join,
  runtime_error,
  print_non_map,
  strftime,
  skboutput,
  // clang-format on
};

class AsyncHandlers {
public:
  const static size_t MAX_TIME_STR_LEN = 64;

  AsyncHandlers(BPFtrace &bpftrace,
                const ast::CDefinitions &c_definitions,
                output::Output &output)
      : bpftrace(bpftrace), c_definitions(c_definitions), out(&output) {};

  Result<> exit(const OpaqueValue &data);
  Result<> join(const OpaqueValue &data);
  Result<> time(const OpaqueValue &data);
  Result<> runtime_error(const OpaqueValue &data);
  Result<> print_non_map(const OpaqueValue &data);
  Result<> print_map(const OpaqueValue &data);
  Result<> zero_map(const OpaqueValue &data);
  Result<> clear_map(const OpaqueValue &data);
  Result<> skboutput(const OpaqueValue &data);
  Result<> syscall(const OpaqueValue &data);
  Result<> cat(const OpaqueValue &data);
  Result<> printf(const OpaqueValue &data);

  void change_output(output::Output &out)
  {
    this->out = &out;
  }

private:
  BPFtrace &bpftrace;
  const ast::CDefinitions &c_definitions;
  output::Output *out;
};

} // namespace bpftrace::async_action
