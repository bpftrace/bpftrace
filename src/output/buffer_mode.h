// Lightweight shared enum for output buffering mode
#pragma once

namespace bpftrace {

enum class OutputBufferConfig {
  UNSET = 0,
  LINE,
  FULL,
  NONE,
};

} // namespace bpftrace
