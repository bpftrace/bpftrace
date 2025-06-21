#pragma once
#include "ast/async_event_types.h"
#include "bpftrace.h"
#include "output.h"

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
  helper_error,
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

  AsyncHandlers(BPFtrace &bpftrace, Output &output)
      : bpftrace(bpftrace), out(output) {};

  void exit(const void *data);
  void join(const void *data);
  void time(const void *data);
  void helper_error(const void *data);
  void print_non_map(const void *data);
  void print_map(const void *data);
  void zero_map(const void *data);
  void clear_map(const void *data);
  void watchpoint_attach(const void *data);
  void watchpoint_detach(const void *data);
  void skboutput(void *data, int size);
  void syscall(AsyncAction printf_id, uint8_t *arg_data);
  void cat(AsyncAction printf_id, uint8_t *arg_data);
  void printf(AsyncAction printf_id, uint8_t *arg_data);

private:
  BPFtrace &bpftrace;
  Output &out;
};

} // namespace bpftrace::async_action
