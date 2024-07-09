#pragma once

#include <set>
#include <string>

#include "bpftrace.h"
#include "required_resources.h"

#include <bpf/bpf.h>
#include <bpf/btf.h>

namespace bpftrace {
namespace globalvars {

static constexpr std::string_view SECTION_NAME = ".rodata";

static constexpr std::string_view NUM_CPUS = "num_cpus";

const std::unordered_set<std::string_view> GLOBAL_VAR_NAMES = {
  NUM_CPUS,
};

void update_global_vars(const struct bpf_object *obj,
                        struct bpf_map *global_vars_map,
                        BPFtrace &bpftrace);

} // namespace globalvars
} // namespace bpftrace
