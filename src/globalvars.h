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
constexpr std::string_view NUM_CPUS = "__bt__num_cpus";
constexpr std::string_view MAX_CPU_ID = "__bt__max_cpu_id";
constexpr std::string_view FMT_STRINGS_BUFFER = "__bt__fmt_str_buf";
constexpr std::string_view TUPLE_BUFFER = "__bt__tuple_buf";
constexpr std::string_view GET_STR_BUFFER = "__bt__get_str_buf";
constexpr std::string_view READ_MAP_VALUE_BUFFER = "__bt__read_map_val_buf";
constexpr std::string_view WRITE_MAP_VALUE_BUFFER = "__bt__write_map_val_buf";
constexpr std::string_view VARIABLE_BUFFER = "__bt__var_buf";
constexpr std::string_view MAP_KEY_BUFFER = "__bt__map_key_buf";
constexpr std::string_view EVENT_LOSS_COUNTER = "__bt__event_loss_counter";

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

enum class GlobalVarType : uint8_t { none, integer };

struct GlobalVarConfig {
  std::string section;
  GlobalVarType type = GlobalVarType::none;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(section, type);
  }
};

const std::unordered_map<std::string_view, GlobalVarConfig>
    GLOBAL_VAR_CONFIGS = {
      { NUM_CPUS,
        { .section = std::string(RO_SECTION_NAME),
          .type = GlobalVarType::integer } },
      { MAX_CPU_ID,
        { .section = std::string(RO_SECTION_NAME),
          .type = GlobalVarType::integer } },
      { EVENT_LOSS_COUNTER,
        { .section = std::string(EVENT_LOSS_COUNTER_SECTION_NAME),
          .type = GlobalVarType::integer } },
      { FMT_STRINGS_BUFFER,
        { .section = std::string(FMT_STRINGS_BUFFER_SECTION_NAME) } },
      { TUPLE_BUFFER, { .section = std::string(TUPLE_BUFFER_SECTION_NAME) } },
      { GET_STR_BUFFER,
        { .section = std::string(GET_STR_BUFFER_SECTION_NAME) } },
      { READ_MAP_VALUE_BUFFER,
        { .section = std::string(READ_MAP_VALUE_BUFFER_SECTION_NAME) } },
      { WRITE_MAP_VALUE_BUFFER,
        { .section = std::string(WRITE_MAP_VALUE_BUFFER_SECTION_NAME) } },
      { VARIABLE_BUFFER,
        { .section = std::string(VARIABLE_BUFFER_SECTION_NAME) } },
      { MAP_KEY_BUFFER,
        { .section = std::string(MAP_KEY_BUFFER_SECTION_NAME) } },
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
  SizedType get_sized_type(const std::string &global_var_name,
                           const RequiredResources &resources,
                           const Config &bpftrace_config) const;

  const std::unordered_map<std::string, GlobalVarConfig> &global_var_map() const
  {
    return global_var_map_;
  }

  void update_global_vars(
      const struct bpf_object *bpf_object,
      const std::unordered_map<std::string, struct bpf_map *> &global_vars_map,
      const std::unordered_map<std::string, int> &known_global_var_values,
      int max_cpu_id);

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
