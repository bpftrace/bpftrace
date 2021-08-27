#pragma once

#include <memory>
#include <string>

#include "bpftrace.h"
#include "required_resources.h"

namespace bpftrace {
namespace aot {

int generate(const RequiredResources &resources,
             const BpfBytecode &bytecode,
             const std::string &out);

int load(BPFtrace &bpftrace, const std::string &in);

} // namespace aot
} // namespace bpftrace
