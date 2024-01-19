#pragma once

#include "bpfbytecode.h"
#include "bpftrace.h"

namespace bpftrace {
namespace elf {

BpfBytecode parseBpfBytecodeFromElfObject(void* const elf);

} // namespace elf
} // namespace bpftrace