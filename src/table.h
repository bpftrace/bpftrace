#pragma once

#include <vector>
#include <cstdint>

std::vector<uint8_t> build_table(
    const std::vector<std::pair<uint64_t, uint64_t>>& entries,
    size_t start, size_t max_size, size_t& out_entries);
