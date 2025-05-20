#pragma once
#include "ast/async_event_types.h"
#include "bpftrace.h"
#include "output.h"

namespace bpftrace::async_action {

const static size_t MAX_TIME_STR_LEN = 64;
void exit_handler(BPFtrace &bpftrace, const void *data);
void join_handler(BPFtrace &bpftrace, Output &out, const void *data);
void time_handler(BPFtrace &bpftrace, Output &out, const void *data);
void helper_error_handler(BPFtrace &bpftrace, Output &out, const void *data);
void print_non_map_handler(BPFtrace &bpftrace, Output &out, const void *data);
void print_map_handler(BPFtrace &bpftrace, Output &out, const void *data);
void zero_map_handler(BPFtrace &bpftrace, const void *data);
void clear_map_handler(BPFtrace &bpftrace, const void *data);
void watchpoint_attach_handler(BPFtrace &bpftrace,
                               Output &out,
                               const void *data);
void watchpoint_detach_handler(BPFtrace &bpftrace, const void *data);
void skboutput_handler(BPFtrace &bpftrace, void *data, int size);
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
