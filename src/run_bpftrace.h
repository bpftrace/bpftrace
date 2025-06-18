#pragma once

#include "bpftrace.h"

int libbpf_print(enum libbpf_print_level level, const char *msg, va_list ap);
void check_is_root();

int run_bpftrace(bpftrace::BPFtrace &bpftrace,
                 bpftrace::Output &output,
                 bpftrace::BpfBytecode &bytecode,
                 std::vector<std::string> &&named_params);
