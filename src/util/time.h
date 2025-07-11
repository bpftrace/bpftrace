#pragma once

#include <chrono>
#include <iostream>

namespace bpftrace::util {

// DisplayUnit is a time display unit.
//
// For convenience, the *value* of each enum is the maximum formatting width
// when printing the fractions of a second in decimal, using the scaling factor
// given.
//
//   auto [unit, scale] = duration_str(d);
//   ... // display seconds, HH:mm:ss or whatever you prefer.
//   if (unit != DisplayUnit::s) {
//     auto ns = (d - std::chrono::floor<std::chrono::seconds>(d)).count();
//     out << '.' << std::setfill('0') << std::setw(unit) << ns/scale;
//   }
//
// This will print a string like: `342.028` if the unit is milliseconds, or a
// string like `342.028234` if the unit is microseconds, etc.
//
// If you are printing the unit itself, this is likely not needed.
enum class DisplayUnit {
  s = 0,
  ms = 3,
  us = 6,
  ns = 9,
};

// Emits the human-readable name for the unit.
std::ostream &operator<<(std::ostream &out, const DisplayUnit &unit);

// Returns a human-readable unit and the scale-factor for a duration.
std::pair<DisplayUnit, uint64_t> duration_str(
    const std::chrono::duration<uint64_t, std::nano> &ns);

} // namespace bpftrace::util
