#include "globalvars.h"

#include "bpftrace.h"
#include "log.h"
#include "utils.h"

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <elf.h>
#include <map>
#include <stdexcept>
#include <sys/mman.h>

namespace bpftrace {
namespace globalvars {

void update_global_vars(const struct bpf_object *bpf_object,
                        struct bpf_map *global_vars_map,
                        BPFtrace &bpftrace)
{
  struct btf *self_btf = bpf_object__btf(bpf_object);

  if (!self_btf) {
    LOG(BUG) << "Failed to get BTF from BPF object";
  }

  __s32 section_id = btf__find_by_name(self_btf,
                                       std::string(SECTION_NAME).c_str());
  if (section_id < 0) {
    LOG(BUG) << "Failed to find section " << SECTION_NAME
             << " to update global vars";
  }

  const struct btf_type *section_type = btf__type_by_id(self_btf,
                                                        (__u32)section_id);
  if (!section_type) {
    LOG(BUG) << "Failed to get BTF type for section " << SECTION_NAME;
  }

  // First locate the offsets of each global variable in the section with btf
  std::map<std::string_view, int> vars_and_offsets;

  for (auto name : GLOBAL_VAR_NAMES) {
    if (bpftrace.resources.needed_global_vars.find(name) ==
        bpftrace.resources.needed_global_vars.end()) {
      continue;
    }
    vars_and_offsets[name] = -1;
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

    if (vars_and_offsets.find(name) != vars_and_offsets.end()) {
      vars_and_offsets[name] = member->offset;
    } else {
      LOG(BUG) << "Unknown global variable " << name;
    }
  }

  size_t v_size;
  char *global_vars_buf = (char *)bpf_map__initial_value(global_vars_map,
                                                         &v_size);

  if (!global_vars_buf) {
    LOG(BUG) << "Failed to get array buf for global variable map";
  }

  // Update the values for the global vars (using the above offsets)
  for (auto [name, offset] : vars_and_offsets) {
    if (offset < 0) {
      LOG(BUG) << "Global variable has not been added to the BPF code "
                  "(codegen_llvm)";
    }

    int64_t *var = (int64_t *)(global_vars_buf + offset);

    if (name == NUM_CPUS) {
      *var = bpftrace.ncpus_;
    }
  }
}

} // namespace globalvars
} // namespace bpftrace
