#include "globalvars.h"

#include "bpftrace.h"
#include "log.h"
#include "types.h"
#include "utils.h"

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <elf.h>
#include <map>
#include <stdexcept>
#include <sys/mman.h>

namespace bpftrace::globalvars {

const GlobalVarConfig &get_config(GlobalVar global_var)
{
  auto it = GLOBAL_VAR_CONFIGS.find(global_var);
  if (it == GLOBAL_VAR_CONFIGS.end()) {
    LOG(BUG) << "Global variable enum not found in GLOBAL_VAR_CONFIGS";
  }
  return it->second;
}

static void verify_maps_found(
    const std::unordered_map<std::string, struct bpf_map *>
        &section_name_to_global_vars_map,
    const BPFtrace &bpftrace)
{
  for (const auto global_var : bpftrace.resources.needed_global_vars) {
    auto config = get_config(global_var);
    if (!section_name_to_global_vars_map.count(config.section)) {
      LOG(BUG) << "No map found for " << config.section
               << " which is needed to set global variable " << config.name;
    }
  }
}

static std::unordered_set<GlobalVar> get_global_vars_for_section(
    std::string_view target_section,
    const BPFtrace &bpftrace)
{
  std::unordered_set<GlobalVar> ret;
  for (const auto global_var : bpftrace.resources.needed_global_vars) {
    auto config = get_config(global_var);
    if (config.section == target_section) {
      ret.insert(global_var);
    }
  }
  return ret;
}

static std::map<GlobalVar, int> find_btf_var_offsets(
    const struct bpf_object *bpf_object,
    std::string_view section_name,
    const std::unordered_set<GlobalVar> &needed_global_vars)
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
  std::map<GlobalVar, int> vars_and_offsets;

  for (const auto global_var : needed_global_vars) {
    vars_and_offsets[global_var] = -1;
  }

  int i;
  struct btf_var_secinfo *member;

  for (i = 0, member = btf_var_secinfos(section_type);
       i < btf_vlen(section_type);
       ++i, ++member) {
    const struct btf_type *type_id = btf__type_by_id(self_btf, member->type);
    if (!type_id) {
      continue;
    }

    std::string_view name = btf__name_by_offset(self_btf, type_id->name_off);

    // Only deal with bpftrace's known global variables. Other global variables
    // could come from imported BPF libraries, for example.
    auto global_var = from_string(name);
    if (global_var)
      vars_and_offsets[*global_var] = member->offset;
  }

  for (const auto &[global_var, offset] : vars_and_offsets) {
    if (offset < 0) {
      LOG(BUG) << "Global variable " << to_string(global_var)
               << " has not been added to the BPF code "
                  "(codegen_llvm)";
    }
  }
  return vars_and_offsets;
}

static void update_global_vars_rodata(
    const struct bpf_object *bpf_object,
    std::string_view section_name,
    struct bpf_map *global_vars_map,
    const std::unordered_set<GlobalVar> &needed_global_vars,
    const BPFtrace &bpftrace)
{
  auto vars_and_offsets = find_btf_var_offsets(bpf_object,
                                               section_name,
                                               needed_global_vars);

  size_t v_size;
  char *global_vars_buf = reinterpret_cast<char *>(
      const_cast<void *>(bpf_map__initial_value(global_vars_map, &v_size)));

  if (!global_vars_buf) {
    LOG(BUG) << "Failed to get array buf for global variable map";
  }

  // Update the values for the global vars (using the above offsets)
  for (const auto &[global_var, offset] : vars_and_offsets) {
    int64_t *var = reinterpret_cast<int64_t *>(global_vars_buf + offset);

    switch (global_var) {
      case GlobalVar::NUM_CPUS:
        *var = bpftrace.ncpus_;
        break;
      case GlobalVar::MAX_CPU_ID:
        *var = bpftrace.max_cpu_id_;
        break;
      case GlobalVar::FMT_STRINGS_BUFFER:
      case GlobalVar::TUPLE_BUFFER:
      case GlobalVar::GET_STR_BUFFER:
      case GlobalVar::READ_MAP_VALUE_BUFFER:
      case GlobalVar::WRITE_MAP_VALUE_BUFFER:
      case GlobalVar::VARIABLE_BUFFER:
      case GlobalVar::MAP_KEY_BUFFER:
        break;
    }
  }
}

static void update_global_vars_custom_rw_section(
    const struct bpf_object *bpf_object,
    const std::string &section_name,
    struct bpf_map *global_vars_map,
    const std::unordered_set<GlobalVar> &needed_global_vars,
    const BPFtrace &bpftrace)
{
  if (needed_global_vars.size() > 1) {
    LOG(BUG) << "Multiple read-write global variables are in same section "
             << section_name;
  }
  auto global_var = *needed_global_vars.begin();

  size_t actual_size;
  auto buf = bpf_map__initial_value(global_vars_map, &actual_size);
  if (!buf) {
    LOG(BUG) << "Failed to get size for section " << section_name
             << " before resizing";
  }
  if (actual_size == 0) {
    LOG(BUG) << "Section " << section_name << " has size of 0 ";
  }

  auto desired_size = (bpftrace.max_cpu_id_ + 1) * actual_size;
  auto err = bpf_map__set_value_size(global_vars_map, desired_size);
  if (err != 0) {
    throw bpftrace::FatalUserException("Failed to set size to " +
                                       std::to_string(desired_size) +
                                       " for section " + section_name);
  }

  buf = bpf_map__initial_value(global_vars_map, &actual_size);
  if (!buf) {
    LOG(BUG) << "Failed to get size for section " << section_name
             << " after resizing";
  }
  if (actual_size != desired_size) {
    throw bpftrace::FatalUserException(
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
    LOG(BUG) << "Read-write global variable " << to_string(global_var)
             << " must be at offset 0 in section " << section_name;
  }
}

void update_global_vars(const struct bpf_object *bpf_object,
                        const std::unordered_map<std::string, struct bpf_map *>
                            &section_name_to_global_vars_map,
                        const BPFtrace &bpftrace)
{
  verify_maps_found(section_name_to_global_vars_map, bpftrace);
  for (const auto &[section_name, global_vars_map] :
       section_name_to_global_vars_map) {
    const auto needed_global_variables = get_global_vars_for_section(
        section_name, bpftrace);
    if (needed_global_variables.empty()) {
      continue;
    }
    if (section_name == RO_SECTION_NAME) {
      update_global_vars_rodata(bpf_object,
                                section_name,
                                global_vars_map,
                                needed_global_variables,
                                bpftrace);
    } else {
      update_global_vars_custom_rw_section(bpf_object,
                                           section_name,
                                           global_vars_map,
                                           needed_global_variables,
                                           bpftrace);
    }
  }
}

std::string to_string(GlobalVar global_var)
{
  return get_config(global_var).name;
}

std::optional<GlobalVar> from_string(std::string_view name)
{
  for (const auto &[global_var, config] : GLOBAL_VAR_CONFIGS) {
    if (config.name == name)
      return global_var;
  }
  return {};
}

static SizedType make_rw_type(size_t num_elements,
                              const SizedType &element_type)
{
  auto subtype = CreateArray(num_elements, element_type);
  // For 1 CPU, will be adjusted to actual CPU count at runtime
  return CreateArray(1, subtype);
}

SizedType get_type(bpftrace::globalvars::GlobalVar global_var,
                   const RequiredResources &resources,
                   const Config &bpftrace_config)
{
  switch (global_var) {
    case bpftrace::globalvars::GlobalVar::NUM_CPUS:
    case bpftrace::globalvars::GlobalVar::MAX_CPU_ID:
      return CreateInt64();
    case bpftrace::globalvars::GlobalVar::FMT_STRINGS_BUFFER:
      assert(resources.max_fmtstring_args_size > 0);
      return make_rw_type(
          1, CreateArray(resources.max_fmtstring_args_size, CreateInt8()));
    case bpftrace::globalvars::GlobalVar::TUPLE_BUFFER:
      assert(resources.max_tuple_size > 0);
      assert(resources.tuple_buffers > 0);
      return make_rw_type(resources.tuple_buffers,
                          CreateArray(resources.max_tuple_size, CreateInt8()));
    case bpftrace::globalvars::GlobalVar::GET_STR_BUFFER: {
      assert(resources.str_buffers > 0);
      const auto max_strlen = bpftrace_config.get(ConfigKeyInt::max_strlen);
      return make_rw_type(resources.str_buffers,
                          CreateArray(max_strlen, CreateInt8()));
    }
    case bpftrace::globalvars::GlobalVar::READ_MAP_VALUE_BUFFER:
      assert(resources.max_read_map_value_size > 0);
      assert(resources.read_map_value_buffers > 0);
      return make_rw_type(resources.read_map_value_buffers,
                          CreateArray(resources.max_read_map_value_size,
                                      CreateInt8()));
    case bpftrace::globalvars::GlobalVar::WRITE_MAP_VALUE_BUFFER:
      assert(resources.max_write_map_value_size > 0);
      return make_rw_type(
          1, CreateArray(resources.max_write_map_value_size, CreateInt8()));
    case GlobalVar::VARIABLE_BUFFER:
      assert(resources.variable_buffers > 0);
      assert(resources.max_variable_size > 0);
      return make_rw_type(resources.variable_buffers,
                          CreateArray(resources.max_variable_size,
                                      CreateInt8()));
    case GlobalVar::MAP_KEY_BUFFER:
      assert(resources.map_key_buffers > 0);
      assert(resources.max_map_key_size > 0);
      return make_rw_type(resources.map_key_buffers,
                          CreateArray(resources.max_map_key_size,
                                      CreateInt8()));
  }
  return {}; // unreachable
}

std::unordered_set<std::string> get_section_names()
{
  std::unordered_set<std::string> ret;
  for (const auto &[_, config] : GLOBAL_VAR_CONFIGS) {
    ret.insert(config.section);
  }
  return ret;
}

} // namespace bpftrace::globalvars
