#pragma once

#include <iostream>

namespace bpftrace::lockdown {

enum class LockdownState {
  None,
  Integrity,
  Confidentiality,
  Unknown, // Could not determine whether lockdown is enabled or not
};

LockdownState detect();
void emit_warning(std::ostream &out);

} //  namespace bpftrace::lockdown
