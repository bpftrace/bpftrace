#pragma once

#include <set>
#include <string>

#include "bpftrace.h"
#include "types.h"

#include <bpf/bpf.h>
#include <bpf/btf.h>

namespace bpftrace {
namespace globalvars {

std::string to_string(GlobalVar global_var);
GlobalVar from_string(std::string_view name);

constexpr std::string_view RO_SECTION_NAME = ".rodata";
constexpr std::string_view FMT_STRINGS_BUFFER_SECTION_NAME =
    ".data.fmt_str_buf";

struct GlobalVarConfig {
  std::string name;
  std::string section;
  bool read_only;
};

const std::unordered_map<GlobalVar, GlobalVarConfig> GLOBAL_VAR_CONFIGS = {
  { GlobalVar::NUM_CPUS, { "num_cpus", std::string(RO_SECTION_NAME), true } },
  { GlobalVar::MAX_CPU_ID,
    { "max_cpu_id", std::string(RO_SECTION_NAME), true } },
  { GlobalVar::FMT_STRINGS_BUFFER,
    { "fmt_str_buf", std::string(FMT_STRINGS_BUFFER_SECTION_NAME), false } },
};

void update_global_vars(
    const struct bpf_object *obj,
    const std::unordered_map<std::string, struct bpf_map *> &global_vars_map,
    const BPFtrace &bpftrace);

const GlobalVarConfig &get_config(GlobalVar global_var);
SizedType get_type(GlobalVar global_var, const RequiredResources &resources);
std::unordered_set<std::string> get_section_names();

} // namespace globalvars
} // namespace bpftrace
