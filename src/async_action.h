#pragma once
#include "bpftrace.h"

namespace bpftrace::async_action {

const static size_t MAX_TIME_STR_LEN = 64;
void join_handler(BPFtrace *bpftrace, void *data);
void time_handler(BPFtrace *bpftrace, void *data);

} // namespace bpftrace::async_action
