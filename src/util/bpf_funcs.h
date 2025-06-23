#pragma once

#include <iostream>

namespace libbpf {
#include "libbpf/bpf.h"

std::ostream &operator<<(std::ostream &out, const bpf_func_id &id);
} // namespace libbpf
