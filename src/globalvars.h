#pragma once

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "types.h"
#include "util/result.h"

namespace bpftrace {

class BPFtrace;
class Config;
class RequiredResources;

namespace globalvars {

class NamedParamError : public ErrorInfo<NamedParamError> {
public:
  NamedParamError(std::string param, std::string value, std::string &&err)
      : param_(std::move(param)),
        value_(std::move(value)),
        err_(std::move(err)) {};
  static char ID;
  void log(llvm::raw_ostream &OS) const override;

  const std::string &err() const
  {
    return err_;
  }

private:
  std::string param_;
  std::string value_;
  std::string err_;
};

class UnknownParamError : public ErrorInfo<UnknownParamError> {
public:
  UnknownParamError(std::vector<std::string> &&unexpected,
                    std::vector<std::string> &&expected)
      : unexpected_(std::move(unexpected)), expected_(std::move(expected)) {};
  static char ID;
  void log(llvm::raw_ostream &OS) const override;

  std::string err() const
  {
    std::string err = "unexpected program command line options: ";
    size_t i;
    bool has_help = false, has_err = false;
    for (i = 0; i < unexpected_.size(); ++i) {
      if (unexpected_[i] == "help") {
        has_help = true;
      } else {
        has_err = true;
        err += "--";
        err += unexpected_[i];
        if (i != unexpected_.size() - 1) {
          err += ", ";
        }
      }
    }
    if (has_help && !has_err) {
      return {};
    } else {
      return err;
    }
  }

  std::string hint() const
  {
    std::string hint = "expected program options: ";

    size_t j;

    if (expected_.empty()) {
      return "no custom program options defined.";
    }

    for (j = 0; j < expected_.size(); ++j) {
      hint += "--";
      hint += expected_[j];
      if (j != expected_.size() - 1) {
        hint += ", ";
      }
    }
    return hint;
  }

private:
  std::vector<std::string> unexpected_;
  std::vector<std::string> expected_;
};

using GlobalVarValue = std::variant<std::string, int64_t, uint64_t, bool>;

using GlobalVarMap = std::unordered_map<std::string, GlobalVarValue>;

// Known global variables
constexpr std::string_view NUM_CPUS = "__bt__num_cpus";
constexpr std::string_view MAX_CPU_ID = "__bt__max_cpu_id";
constexpr std::string_view FMT_STRINGS_BUFFER = "__bt__fmt_str_buf";
constexpr std::string_view TUPLE_BUFFER = "__bt__tuple_buf";
constexpr std::string_view CALL_STACK_BUFFER = "__bt__call_stack_buf";
constexpr std::string_view GET_STR_BUFFER = "__bt__get_str_buf";
constexpr std::string_view READ_MAP_VALUE_BUFFER = "__bt__read_map_val_buf";
constexpr std::string_view WRITE_MAP_VALUE_BUFFER = "__bt__write_map_val_buf";
constexpr std::string_view VARIABLE_BUFFER = "__bt__var_buf";
constexpr std::string_view MAP_KEY_BUFFER = "__bt__map_key_buf";
constexpr std::string_view EVENT_LOSS_COUNTER = "__bt__event_loss_counter";
constexpr std::string_view JOIN_BUFFER = "__bt__join_buf";

// Section names
constexpr std::string_view RO_SECTION_NAME = ".rodata";
constexpr std::string_view FMT_STRINGS_BUFFER_SECTION_NAME =
    ".data.fmt_str_buf";
constexpr std::string_view TUPLE_BUFFER_SECTION_NAME = ".data.tuple_buf";
constexpr std::string_view CALL_STACK_BUFFER_SECTION_NAME = ".data.call_stack_buf";
constexpr std::string_view GET_STR_BUFFER_SECTION_NAME = ".data.get_str_buf";
constexpr std::string_view READ_MAP_VALUE_BUFFER_SECTION_NAME =
    ".data.read_map_val_buf";
constexpr std::string_view WRITE_MAP_VALUE_BUFFER_SECTION_NAME =
    ".data.write_map_val_buf";
constexpr std::string_view VARIABLE_BUFFER_SECTION_NAME = ".data.var_buf";
constexpr std::string_view MAP_KEY_BUFFER_SECTION_NAME = ".data.map_key_buf";
constexpr std::string_view EVENT_LOSS_COUNTER_SECTION_NAME =
    ".data.event_loss_counter";
constexpr std::string_view JOIN_BUFFER_SECTION_NAME =
    ".data.join_buf";

struct GlobalVarConfig {
  std::string section;
  enum Type {
    opt_bool,
    opt_string,
    opt_signed,
    opt_unsigned,
  };
  std::optional<Type> type = std::nullopt;

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
        { .section = std::string(RO_SECTION_NAME), .type = GlobalVarConfig::opt_unsigned } },
      { MAX_CPU_ID,
        { .section = std::string(RO_SECTION_NAME), .type = GlobalVarConfig::opt_unsigned } },
      { EVENT_LOSS_COUNTER,
        { .section = std::string(EVENT_LOSS_COUNTER_SECTION_NAME),
          .type = GlobalVarConfig::opt_unsigned } },
      { FMT_STRINGS_BUFFER,
        { .section = std::string(FMT_STRINGS_BUFFER_SECTION_NAME) } },
      { TUPLE_BUFFER, { .section = std::string(TUPLE_BUFFER_SECTION_NAME) } },
      { CALL_STACK_BUFFER, { .section = std::string(CALL_STACK_BUFFER_SECTION_NAME) } },
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
      { JOIN_BUFFER,
        { .section = std::string(JOIN_BUFFER_SECTION_NAME) } },
    };

class GlobalVars {
public:
  GlobalVars() = default;
  GlobalVars(std::unordered_map<std::string, GlobalVarConfig> global_var_map,
             std::unordered_map<std::string, GlobalVarValue> default_values)
      : added_global_vars_(std::move(global_var_map)),
        named_param_defaults_(std::move(default_values))
  {
  }

  void add_known(const std::string_view &name);
  void add_named_param(const std::string &name,
                       const GlobalVarValue &default_value);
  Result<GlobalVarMap> get_named_param_vals(
      std::vector<std::string> raw_named_params) const;
  const GlobalVarConfig &get_config(const std::string &name) const;
  SizedType get_sized_type(const std::string &global_var_name,
                           const RequiredResources &resources,
                           const Config &bpftrace_config) const;
  void check_index(const std::string &global_var_name, const RequiredResources &resources, size_t index) const;

  const std::unordered_map<std::string, GlobalVarConfig> &global_var_map() const
  {
    return added_global_vars_;
  }

  void update_global_vars(
      const struct bpf_object *bpf_object,
      const std::unordered_map<std::string, struct bpf_map *> &global_vars_map,
      GlobalVarMap &&global_var_vals,
      uint64_t ncpus,
      uint64_t max_cpu_id);

  std::unordered_set<std::string> get_global_vars_for_section(
      std::string_view target_section);
  uint64_t *get_global_var(
      const struct bpf_object *bpf_object,
      std::string_view target_section,
      const std::unordered_map<std::string, struct bpf_map *>
          &section_name_to_global_vars_map);

protected:
  std::unordered_map<std::string, GlobalVarConfig> added_global_vars_;
  std::unordered_map<std::string, GlobalVarValue> named_param_defaults_;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(added_global_vars_, named_param_defaults_);
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
