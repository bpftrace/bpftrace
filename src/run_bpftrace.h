#pragma once

#include "bpftrace.h"

int libbpf_print(enum libbpf_print_level level, const char *msg, va_list ap);

int run_bpftrace(bpftrace::BPFtrace &bpftrace, bpftrace::BpfBytecode &bytecode);
