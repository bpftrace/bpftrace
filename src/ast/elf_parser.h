#pragma once

#include "bpftrace.h"

namespace bpftrace {
namespace elf {

BpfBytecode parseBpfBytecodeFromElfObject(void* const elf);

} // namespace elf
} // namespace bpftrace