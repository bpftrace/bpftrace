#pragma once

#include <optional>
#include <string>

#include "bpftrace.h"
#include "types.h"

#include <bpf/bpf.h>
#include <bpf/btf.h>

namespace bpftrace::globalvars {

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
  { GlobalVar::NUM_CPUS,
    { .name = "num_cpus",
      .section = std::string(RO_SECTION_NAME),
      .read_only = true } },
  { GlobalVar::MAX_CPU_ID,
    { .name = "max_cpu_id",
      .section = std::string(RO_SECTION_NAME),
      .read_only = true } },
  { GlobalVar::FMT_STRINGS_BUFFER,
    { .name = "fmt_str_buf",
      .section = std::string(FMT_STRINGS_BUFFER_SECTION_NAME),
      .read_only = false } },
  { GlobalVar::TUPLE_BUFFER,
    { .name = "tuple_buf",
      .section = std::string(TUPLE_BUFFER_SECTION_NAME),
      .read_only = false } },
  { GlobalVar::GET_STR_BUFFER,
    { .name = "get_str_buf",
      .section = std::string(GET_STR_BUFFER_SECTION_NAME),
      .read_only = false } },
  { GlobalVar::READ_MAP_VALUE_BUFFER,
    { .name = "read_map_val_buf",
      .section = std::string(READ_MAP_VALUE_BUFFER_SECTION_NAME),
      .read_only = false } },
  { GlobalVar::WRITE_MAP_VALUE_BUFFER,
    { .name = "write_map_val_buf",
      .section = std::string(WRITE_MAP_VALUE_BUFFER_SECTION_NAME),
      .read_only = false } },
  { GlobalVar::VARIABLE_BUFFER,
    { .name = "var_buf",
      .section = std::string(VARIABLE_BUFFER_SECTION_NAME),
      .read_only = false } },
  { GlobalVar::MAP_KEY_BUFFER,
    { .name = "map_key_buf",
      .section = std::string(MAP_KEY_BUFFER_SECTION_NAME),
      .read_only = false } },
};

void update_global_vars(
    const struct bpf_object *bpf_object,
    const std::unordered_map<std::string, struct bpf_map *> &global_vars_map,
    const BPFtrace &bpftrace);

const GlobalVarConfig &get_config(GlobalVar global_var);
SizedType get_type(GlobalVar global_var,
                   const RequiredResources &resources,
                   const Config &bpftrace_config);
std::unordered_set<std::string> get_section_names();

} // namespace bpftrace::globalvars
