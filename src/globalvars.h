#pragma once

#include <optional>
#include <set>
#include <string>

#include "bpftrace.h"
#include "types.h"

#include <bpf/bpf.h>
#include <bpf/btf.h>

namespace bpftrace {
namespace globalvars {

std::string to_string(GlobalVar global_var);
std::optional<GlobalVar> from_string(std::string_view name);

constexpr std::string_view RO_SECTION_NAME = ".rodata";
constexpr std::string_view FMT_STRINGS_BUFFER_SECTION_NAME =
    ".data.fmt_str_buf";
constexpr std::string_view TUPLE_BUFFER_SECTION_NAME = ".data.tuple_buf";
constexpr std::string_view GET_STR_BUFFER_SECTION_NAME = ".data.get_str_buf";
constexpr std::string_view READ_MAP_VALUE_BUFFER_SECTION_NAME =
    ".data.read_map_val_buf";
constexpr std::string_view WRITE_MAP_VALUE_BUFFER_SECTION_NAME =
    ".data.write_map_val_buf";
constexpr std::string_view VARIABLE_BUFFER_SECTION_NAME = ".data.var_buf";
constexpr std::string_view MAP_KEY_BUFFER_SECTION_NAME = ".data.map_key_buf";

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
  { GlobalVar::TUPLE_BUFFER,
    { "tuple_buf", std::string(TUPLE_BUFFER_SECTION_NAME), false } },
  { GlobalVar::GET_STR_BUFFER,
    { "get_str_buf", std::string(GET_STR_BUFFER_SECTION_NAME), false } },
  { GlobalVar::READ_MAP_VALUE_BUFFER,
    { "read_map_val_buf",
      std::string(READ_MAP_VALUE_BUFFER_SECTION_NAME),
      false } },
  { GlobalVar::WRITE_MAP_VALUE_BUFFER,
    { "write_map_val_buf",
      std::string(WRITE_MAP_VALUE_BUFFER_SECTION_NAME),
      false } },
  { GlobalVar::VARIABLE_BUFFER,
    { "var_buf", std::string(VARIABLE_BUFFER_SECTION_NAME), false } },
  { GlobalVar::MAP_KEY_BUFFER,
    { "map_key_buf", std::string(MAP_KEY_BUFFER_SECTION_NAME), false } },
};

void update_global_vars(
    const struct bpf_object *obj,
    const std::unordered_map<std::string, struct bpf_map *> &global_vars_map,
    const BPFtrace &bpftrace);

const GlobalVarConfig &get_config(GlobalVar global_var);
SizedType get_type(GlobalVar global_var,
                   const RequiredResources &resources,
                   const Config &bpftrace_config);
std::unordered_set<std::string> get_section_names();

} // namespace globalvars
} // namespace bpftrace
