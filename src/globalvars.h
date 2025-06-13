#pragma once

#include "log.h"
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "types.h"

namespace bpftrace {

class BPFtrace;
class Config;
class RequiredResources;

namespace globalvars {

// Known global variables
constexpr std::string_view NUM_CPUS = "num_cpus";
constexpr std::string_view MAX_CPU_ID = "max_cpu_id";
constexpr std::string_view FMT_STRINGS_BUFFER = "fmt_str_buf";
constexpr std::string_view TUPLE_BUFFER = "tuple_buf";
constexpr std::string_view GET_STR_BUFFER = "get_str_buf";
constexpr std::string_view READ_MAP_VALUE_BUFFER = "read_map_val_buf";
constexpr std::string_view WRITE_MAP_VALUE_BUFFER = "write_map_val_buf";
constexpr std::string_view VARIABLE_BUFFER = "var_buf";
constexpr std::string_view MAP_KEY_BUFFER = "map_key_buf";
constexpr std::string_view EVENT_LOSS_COUNTER = "event_loss_counter";

// Section names
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
constexpr std::string_view EVENT_LOSS_COUNTER_SECTION_NAME =
    ".data.event_loss_counter";

struct GlobalVarConfig {
  std::string section;
  bool read_only;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(section, read_only);
  }
};

struct KnownGlobalVarValues {
  int num_cpus;
  int max_cpu_id;
};

const std::unordered_map<std::string_view, GlobalVarConfig>
    GLOBAL_VAR_CONFIGS = {
      { NUM_CPUS,
        { .section = std::string(RO_SECTION_NAME), .read_only = true } },
      { MAX_CPU_ID,
        { .section = std::string(RO_SECTION_NAME), .read_only = true } },
      { FMT_STRINGS_BUFFER,
        { .section = std::string(FMT_STRINGS_BUFFER_SECTION_NAME),
          .read_only = false } },
      { TUPLE_BUFFER,
        { .section = std::string(TUPLE_BUFFER_SECTION_NAME),
          .read_only = false } },
      { GET_STR_BUFFER,
        { .section = std::string(GET_STR_BUFFER_SECTION_NAME),
          .read_only = false } },
      { READ_MAP_VALUE_BUFFER,
        { .section = std::string(READ_MAP_VALUE_BUFFER_SECTION_NAME),
          .read_only = false } },
      { WRITE_MAP_VALUE_BUFFER,
        { .section = std::string(WRITE_MAP_VALUE_BUFFER_SECTION_NAME),
          .read_only = false } },
      { VARIABLE_BUFFER,
        { .section = std::string(VARIABLE_BUFFER_SECTION_NAME),
          .read_only = false } },
      { MAP_KEY_BUFFER,
        { .section = std::string(MAP_KEY_BUFFER_SECTION_NAME),
          .read_only = false } },
      { EVENT_LOSS_COUNTER,
        { .section = std::string(EVENT_LOSS_COUNTER_SECTION_NAME),
          .read_only = false } },
    };

class GlobalVars {
public:
  GlobalVars() = default;
  GlobalVars(std::unordered_map<std::string, GlobalVarConfig> global_var_map)
      : global_var_map_(std::move(global_var_map))
  {
  }

  void add_known_global_var(const std::string_view &name);
  const GlobalVarConfig &get_config(const std::string &name) const;

  const std::unordered_map<std::string, GlobalVarConfig> &global_var_map() const
  {
    return global_var_map_;
  }

  void update_global_vars(
      const struct bpf_object *bpf_object,
      const std::unordered_map<std::string, struct bpf_map *> &global_vars_map,
      KnownGlobalVarValues known_global_var_values);

  std::unordered_set<std::string> get_global_vars_for_section(
      std::string_view target_section);
  uint64_t get_global_var(
      const struct bpf_object *bpf_object,
      std::string_view target_section,
      const std::unordered_map<std::string, struct bpf_map *>
          &section_name_to_global_vars_map);

protected:
  std::unordered_map<std::string, GlobalVarConfig> global_var_map_;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(global_var_map_);
  }

  void verify_maps_found(const std::unordered_map<std::string, struct bpf_map *>
                             &section_name_to_global_vars_map);
};

SizedType get_type(const std::string &global_var_name,
                   const RequiredResources &resources,
                   const Config &bpftrace_config);
std::unordered_set<std::string> get_section_names();

} // namespace globalvars
} // namespace bpftrace
