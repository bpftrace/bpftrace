#pragma once
#include "ast/async_event_types.h"
#include "bpftrace.h"
#include "output.h"

namespace bpftrace::async_action {

const static size_t MAX_TIME_STR_LEN = 64;
void join_handler(BPFtrace &bpftrace, Output &out, void *data);
void time_handler(BPFtrace &bpftrace, Output &out, void *data);
void helper_error_handler(BPFtrace &bpftrace, Output &out, void *data);
void syscall_handler(BPFtrace &bpftrace,
                     Output &out,
                     AsyncAction printf_id,
                     uint8_t *arg_data);
void cat_handler(BPFtrace &bpftrace,
                 Output &out,
                 AsyncAction printf_id,
                 uint8_t *arg_data);
void printf_handler(BPFtrace &bpftrace,
                    Output &out,
                    AsyncAction printf_id,
                    uint8_t *arg_data);

} // namespace bpftrace::async_action
