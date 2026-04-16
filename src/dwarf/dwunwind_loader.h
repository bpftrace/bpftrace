#pragma once

#include <cstdint>
#include <map>
#include <vector>

#include "bpfbytecode.h"
#include "dwarf/dwunwind.h"

namespace bpftrace {

int parse_dwarf_unwind(
    BpfBytecode &bytecode,
    const std::vector<pid_t> &pids,
    std::map<TableType, std::vector<std::vector<uint8_t>>> &unwind_data,
    std::map<uint32_t, std::vector<uint8_t>> &unwind_mappings);

int feed_dwarf_unwind(
    BpfBytecode &bytecode,
    const std::map<TableType, std::vector<std::vector<uint8_t>>> &unwind_data,
    const std::map<uint32_t, std::vector<uint8_t>> &unwind_mappings);

} // namespace bpftrace
