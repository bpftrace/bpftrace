#pragma once

#include <cstdint>
#include <vector>

// Build the main table for dwarf unwinding.
// This table maps a file offset into a specific elf file to an entry with
// the actual unwind instructions.
// Data is encoded as a compact binary tree suitable for lower bound style
// lookups.
// See dwundind_table.cpp for details of the encoding.
std::vector<uint8_t> dwunwind_build_table(
    const std::vector<std::pair<uint64_t, uint64_t>>& entries,
    size_t start,
    size_t max_size,
    size_t& out_entries);
