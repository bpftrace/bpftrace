#pragma once

#include <cstdint>

namespace bpftrace::util {

uint32_t round_up_to_next_power_of_two(uint32_t n);

} // namespace bpftrace::util
