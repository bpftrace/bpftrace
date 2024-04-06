#pragma once

#include <memory>
#include <string>

#include "bpftrace.h"
#include "required_resources.h"

namespace bpftrace {
namespace aot {

static constexpr std::string_view AOT_SHIM_NAME = "bpftrace-aotrt";

int generate(const RequiredResources &resources,
             const std::string &out,
             void *const elf,
             size_t elf_size);

int load(BPFtrace &bpftrace, const std::string &in);

} // namespace aot
} // namespace bpftrace
