#pragma once

#include "bpfbytecode.h"
#include "bpftrace.h"

namespace bpftrace {
namespace elf {

BpfBytecode parseBpfBytecodeFromElfObject(void *const elf, size_t elf_size);

} // namespace elf
} // namespace bpftrace
