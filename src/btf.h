#pragma once

#include "types.h"
#include <cstddef>
#include <linux/types.h>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <string>
#include <unistd.h>
#include <unordered_set>

struct btf;
struct btf_type;

namespace bpftrace {

class BPFtrace;

class BTF
{
  enum state
  {
    NODATA,
    OK,
  };

  // BTF object for vmlinux or a kernel module.
  // We're currently storing its name and BTF id.
  struct BTFObj
  {
    struct btf* btf;
    __u32 id;
    std::string name;
  };

  // It is often necessary to store a BTF id along with the BTF data containing
  // its definition.
  struct BTFId
  {
    struct btf* btf;
    __u32 id;
  };

public:
  BTF(const std::set<std::string>& modules);
  BTF(BPFtrace* bpftrace, const std::set<std::string>& modules) : BTF(modules)
  {
    bpftrace_ = bpftrace;
  };
  ~BTF();

  bool has_data(void) const;
  size_t objects_cnt() const
  {
    return btf_objects.size();
  }
  std::string c_def(const std::unordered_set<std::string>& set) const;
  std::string type_of(const std::string& name, const std::string& field);
  std::string type_of(const BTFId& type_id, const std::string& field);
  SizedType get_stype(const std::string& type_name);

  std::set<std::string> get_all_structs() const;
  std::unique_ptr<std::istream> get_all_funcs() const;
  std::unordered_set<std::string> get_all_iters() const;
  std::map<std::string, std::vector<std::string>> get_params(
      const std::set<std::string>& funcs) const;

  Struct resolve_args(const std::string& func, bool ret);
  void resolve_fields(SizedType& type);

  std::pair<int, int> get_btf_id_fd(const std::string& func,
                                    const std::string& mod) const;

private:
  void load_kernel_btfs(const std::set<std::string>& modules);
  SizedType get_stype(const BTFId& btf_id, bool resolve_structs = true);
  void resolve_fields(const BTFId& type_id, Struct* record, __u32 start_offset);
  const struct btf_type* btf_type_skip_modifiers(const struct btf_type* t,
                                                 const struct btf* btf);
  BTF::BTFId find_id(const std::string& name,
                     std::optional<__u32> kind = std::nullopt) const;
  __s32 find_id_in_btf(struct btf* btf,
                       const std::string& name,
                       std::optional<__u32> = std::nullopt) const;

  std::string dump_defs_from_btf(const struct btf* btf,
                                 std::unordered_set<std::string>& types) const;
  std::string get_all_funcs_from_btf(const BTFObj& btf_obj) const;
  std::map<std::string, std::vector<std::string>> get_params_from_btf(
      const BTFObj& btf_obj,
      const std::set<std::string>& funcs) const;
  std::set<std::string> get_all_structs_from_btf(const struct btf* btf) const;
  std::unordered_set<std::string> get_all_iters_from_btf(
      const struct btf* btf) const;

  __s32 start_id(const struct btf* btf) const;

  struct btf* vmlinux_btf = nullptr;
  __s32 vmlinux_btf_size;
  // BTF objects for vmlinux and modules
  std::vector<BTFObj> btf_objects;
  enum state state = NODATA;
  BPFtrace* bpftrace_ = nullptr;
};

inline bool BTF::has_data(void) const
{
  return state == OK;
}

} // namespace bpftrace
