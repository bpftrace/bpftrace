#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <elf.h>
#include <sys/mman.h>

#include "bpftrace.h"
#include "globalvars.h"
#include "log.h"
#include "required_resources.h"
#include "types.h"
#include "util/exceptions.h"

namespace bpftrace::globalvars {

static std::map<std::string, int> find_btf_var_offsets(
    const struct bpf_object *bpf_object,
    std::string_view section_name,
    const std::unordered_set<std::string> &needed_global_vars)
{
  struct btf *self_btf = bpf_object__btf(bpf_object);

  if (!self_btf) {
    LOG(BUG) << "Failed to get BTF from BPF object";
  }

  __s32 section_id = btf__find_by_name(self_btf,
                                       std::string(section_name).c_str());
  if (section_id < 0) {
    LOG(BUG) << "Failed to find section " << section_name
             << " to update global vars";
  }

  const struct btf_type *section_type = btf__type_by_id(
      self_btf, static_cast<__u32>(section_id));
  if (!section_type) {
    LOG(BUG) << "Failed to get BTF type for section " << section_name;
  }

  // First locate the offsets of each global variable in the section with btf
  std::map<std::string, int> vars_and_offsets;

  for (const auto &global_var : needed_global_vars) {
    vars_and_offsets[global_var] = -1;
  }

  uint16_t i;
  struct btf_var_secinfo *member;

  for (i = 0, member = btf_var_secinfos(section_type);
       i < btf_vlen(section_type);
       ++i, ++member) {
    const struct btf_type *type_id = btf__type_by_id(self_btf, member->type);
    if (!type_id) {
      continue;
    }

    std::string name = std::string(
        btf__name_by_offset(self_btf, type_id->name_off));

    // Only deal with bpftrace's known global variables. Other global variables
    // could come from imported BPF libraries, for example.
    auto it = vars_and_offsets.find(name);
    if (it != vars_and_offsets.end()) {
      it->second = member->offset;
    }
  }

  for (const auto &[global_var, offset] : vars_and_offsets) {
    if (offset < 0) {
      LOG(BUG) << "Global variable " << global_var
               << " has not been added to the BPF code "
                  "(codegen_llvm)";
    }
  }
  return vars_and_offsets;
}

void update_global_vars_rodata(
    const struct bpf_object *bpf_object,
    std::string_view section_name,
    struct bpf_map *global_vars_map,
    const std::unordered_set<std::string> &needed_global_vars,
    const KnownGlobalVarValues &known_global_var_values)
{
  auto vars_and_offsets = find_btf_var_offsets(bpf_object,
                                               section_name,
                                               needed_global_vars);

  size_t v_size;
  char *global_vars_buf = reinterpret_cast<char *>(
      bpf_map__initial_value(global_vars_map, &v_size));

  if (!global_vars_buf) {
    LOG(BUG) << "Failed to get array buf for global variable map";
  }

  // Update the values for the global vars (using the above offsets)
  for (const auto &[global_var, offset] : vars_and_offsets) {
    auto *var = reinterpret_cast<int64_t *>(global_vars_buf + offset);

    if (global_var == NUM_CPUS) {
      *var = known_global_var_values.num_cpus;
    } else if (global_var == MAX_CPU_ID) {
      *var = known_global_var_values.max_cpu_id;
    }
  }
}

void update_global_vars_custom_rw_section(
    const struct bpf_object *bpf_object,
    const std::string &section_name,
    struct bpf_map *global_vars_map,
    const std::unordered_set<std::string> &needed_global_vars,
    int max_cpu_id)
{
  if (needed_global_vars.size() > 1) {
    LOG(BUG) << "Multiple read-write global variables are in same section "
             << section_name;
  }
  auto global_var = *needed_global_vars.begin();

  size_t actual_size;
  auto *buf = bpf_map__initial_value(global_vars_map, &actual_size);
  if (!buf) {
    LOG(BUG) << "Failed to get size for section " << section_name
             << " before resizing";
  }
  if (actual_size == 0) {
    LOG(BUG) << "Section " << section_name << " has size of 0 ";
  }

  auto desired_size = (max_cpu_id + 1) * actual_size;
  auto err = bpf_map__set_value_size(global_vars_map, desired_size);
  if (err != 0) {
    throw util::FatalUserException("Failed to set size to " +
                                   std::to_string(desired_size) +
                                   " for section " + section_name);
  }

  buf = bpf_map__initial_value(global_vars_map, &actual_size);
  if (!buf) {
    LOG(BUG) << "Failed to get size for section " << section_name
             << " after resizing";
  }
  if (actual_size != desired_size) {
    throw util::FatalUserException(
        "Failed to set size from " + std::to_string(actual_size) + " to " +
        std::to_string(desired_size) + " for section " + section_name);
  }

  // No need to memset to zero as we memset on each usage

  // Verify we can still find variable name via BTF and it hasn't been cleared
  // after size changes
  auto vars_and_offset = find_btf_var_offsets(bpf_object,
                                              section_name,
                                              needed_global_vars);
  if (vars_and_offset.at(global_var) != 0) {
    LOG(BUG) << "Read-write global variable " << global_var
             << " must be at offset 0 in section " << section_name;
  }
}

static SizedType make_rw_type(size_t num_elements,
                              const SizedType &element_type)
{
  auto subtype = CreateArray(num_elements, element_type);
  // For 1 CPU, will be adjusted to actual CPU count at runtime
  return CreateArray(1, subtype);
}

SizedType get_type(const std::string &global_var_name,
                   const RequiredResources &resources,
                   const Config &bpftrace_config)
{
  if (global_var_name == NUM_CPUS || global_var_name == MAX_CPU_ID) {
    return CreateInt64();
  }

  if (global_var_name == FMT_STRINGS_BUFFER) {
    assert(resources.max_fmtstring_args_size > 0);
    return make_rw_type(
        1, CreateArray(resources.max_fmtstring_args_size, CreateInt8()));
  }

  if (global_var_name == TUPLE_BUFFER) {
    assert(resources.max_tuple_size > 0);
    assert(resources.tuple_buffers > 0);
    return make_rw_type(resources.tuple_buffers,
                        CreateArray(resources.max_tuple_size, CreateInt8()));
  }

  if (global_var_name == GET_STR_BUFFER) {
    assert(resources.str_buffers > 0);
    const auto max_strlen = bpftrace_config.max_strlen;
    return make_rw_type(resources.str_buffers,
                        CreateArray(max_strlen, CreateInt8()));
  }

  if (global_var_name == READ_MAP_VALUE_BUFFER) {
    assert(resources.max_read_map_value_size > 0);
    assert(resources.read_map_value_buffers > 0);
    return make_rw_type(resources.read_map_value_buffers,
                        CreateArray(resources.max_read_map_value_size,
                                    CreateInt8()));
  }

  if (global_var_name == WRITE_MAP_VALUE_BUFFER) {
    assert(resources.max_write_map_value_size > 0);
    return make_rw_type(
        1, CreateArray(resources.max_write_map_value_size, CreateInt8()));
  }

  if (global_var_name == VARIABLE_BUFFER) {
    assert(resources.variable_buffers > 0);
    assert(resources.max_variable_size > 0);
    return make_rw_type(resources.variable_buffers,
                        CreateArray(resources.max_variable_size, CreateInt8()));
  }

  if (global_var_name == MAP_KEY_BUFFER) {
    assert(resources.map_key_buffers > 0);
    assert(resources.max_map_key_size > 0);
    return make_rw_type(resources.map_key_buffers,
                        CreateArray(resources.max_map_key_size, CreateInt8()));
  }

  if (global_var_name == EVENT_LOSS_COUNTER) {
    return CreateUInt64();
  }

  LOG(BUG) << "Unknown global variable " << global_var_name;
  return CreateUInt64();
}

std::unordered_set<std::string> get_section_names()
{
  std::unordered_set<std::string> ret;
  for (const auto &[_, config] : GLOBAL_VAR_CONFIGS) {
    ret.insert(config.section);
  }
  return ret;
}

void GlobalVars::add_known_global_var(const std::string_view &name)
{
  if (!GLOBAL_VAR_CONFIGS.contains(name)) {
    LOG(BUG) << "Unknown global variable: " << name;
  }
  auto str_name = std::string(name);

  if (global_var_map_.contains(str_name)) {
    return;
  }
  global_var_map_[std::move(str_name)] = GLOBAL_VAR_CONFIGS.at(name);
}

const GlobalVarConfig &GlobalVars::get_config(const std::string &name) const
{
  auto it = global_var_map_.find(name);
  if (it == global_var_map_.end()) {
    LOG(BUG) << "Unknown global variable: " << name;
  }
  return it->second;
}

void GlobalVars::verify_maps_found(
    const std::unordered_map<std::string, struct bpf_map *>
        &section_name_to_global_vars_map)
{
  for (const auto &[name, config] : global_var_map_) {
    if (!section_name_to_global_vars_map.contains(config.section)) {
      LOG(BUG) << "No map found in " << config.section
               << " which is needed to set global variable " << name;
    }
  }
}

std::unordered_set<std::string> GlobalVars::get_global_vars_for_section(
    std::string_view target_section)
{
  std::unordered_set<std::string> ret;
  for (const auto &[name, config] : global_var_map_) {
    if (config.section == target_section) {
      ret.insert(name);
    }
  }
  return ret;
}

void GlobalVars::update_global_vars(
    const struct bpf_object *bpf_object,
    const std::unordered_map<std::string, struct bpf_map *>
        &section_name_to_global_vars_map,
    KnownGlobalVarValues known_global_var_values)
{
  verify_maps_found(section_name_to_global_vars_map);
  for (const auto &[section_name, global_vars_map] :
       section_name_to_global_vars_map) {
    const auto needed_global_variables = get_global_vars_for_section(
        section_name);
    if (needed_global_variables.empty()) {
      continue;
    }
    if (section_name == RO_SECTION_NAME) {
      update_global_vars_rodata(bpf_object,
                                section_name,
                                global_vars_map,
                                needed_global_variables,
                                known_global_var_values);
    } else if (section_name != EVENT_LOSS_COUNTER_SECTION_NAME) {
      update_global_vars_custom_rw_section(bpf_object,
                                           section_name,
                                           global_vars_map,
                                           needed_global_variables,
                                           known_global_var_values.max_cpu_id);
    }
  }
}

uint64_t GlobalVars::get_global_var(
    const struct bpf_object *bpf_object,
    std::string_view target_section,
    const std::unordered_map<std::string, struct bpf_map *>
        &section_name_to_global_vars_map)
{
  verify_maps_found(section_name_to_global_vars_map);

  auto it = std::ranges::find_if(section_name_to_global_vars_map,
                                 [target_section](const auto &pair) {
                                   return pair.first == target_section;
                                 });

  if (it == section_name_to_global_vars_map.end()) {
    LOG(BUG) << target_section << " not found";
  }

  const auto &[section_name, global_vars_map] = *it;

  const auto needed_global_variables = get_global_vars_for_section(
      section_name);

  if (needed_global_variables.empty()) {
    LOG(BUG) << "No global variables found in section " << section_name;
  } else if (needed_global_variables.size() > 1) {
    LOG(BUG) << "Multiple read-write global variables are in same section "
             << section_name;
  }

  auto global_var = *needed_global_variables.begin();
  auto vars_and_offsets = find_btf_var_offsets(bpf_object,
                                               section_name,
                                               needed_global_variables);

  if (vars_and_offsets.at(global_var) != 0) {
    LOG(BUG) << "Read-write global variable " << global_var
             << " must be at offset 0 in section " << section_name;
  }

  size_t v_size;
  auto *target_var = reinterpret_cast<uint64_t *>(
      bpf_map__initial_value(global_vars_map, &v_size));

  if (!target_var) {
    LOG(BUG) << "Failed to get array buf for global variable map";
  }

  return *target_var;
}

} // namespace bpftrace::globalvars
