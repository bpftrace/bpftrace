#pragma once

#include "types.h"

#include <cstddef>
#include <linux/btf.h>
#include <linux/types.h>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <unistd.h>
#include <unordered_set>

#include "ast/pass_manager.h"

// Taken from libbpf
#define BTF_INFO_ENC(kind, kind_flag, vlen)                                    \
  ((!!(kind_flag) << 31) | ((kind) << 24) | ((vlen) & BTF_MAX_VLEN))
#define BTF_TYPE_ENC(name, info, size_or_type) (name), (info), (size_or_type)
#define BTF_INT_ENC(encoding, bits_offset, nr_bits)                            \
  ((encoding) << 24 | (bits_offset) << 16 | (nr_bits))
#define BTF_TYPE_INT_ENC(name, encoding, bits_offset, bits, sz)                \
  BTF_TYPE_ENC(name, BTF_INFO_ENC(BTF_KIND_INT, 0, 0), sz),                    \
      BTF_INT_ENC(encoding, bits_offset, bits)
#define BTF_PARAM_ENC(name, type) (name), (type)

struct btf;
struct btf_type;

namespace bpftrace {

// Note: there are several prefixes for raw tracepoint BTF functions.
// "__probestub_" seems to be the most accurate in terms of getting the params
// but it wasn't added until May 2023 so older kernels might not have it,
// which is why we also check "__traceiter_" (as needed).
// "btf_trace_" prefix, which is what the kernel uses for raw tracepoints, we
// use in bpfprogram.cpp to validate if we can attach to this raw tracepoint.
// The BTF for "btf_trace_" is a typedef that eventually resolves to a
// FUNC_PROTO but the params for this do not have names, which is what we need.
// "__probestub_" was added here:
// https://lore.kernel.org/all/168507471874.913472.17214624519622959593.stgit@mhiramat.roam.corp.google.com/
// "__traceiter_" was added here:
// https://lore.kernel.org/all/20200908105743.GW2674@hirez.programming.kicks-ass.net/
static const std::vector<std::string> RT_BTF_PREFIXES = { "__probestub_",
                                                          "__traceiter_" };

class BPFtrace;

using FuncParamLists = std::map<std::string, std::vector<std::string>>;

class BTF {
  enum state {
    INIT,
    ERROR,
    VMLINUX_LOADED,
    VMLINUX_AND_MODULES_LOADED,
  };

  // BTF object for vmlinux or a kernel module.
  // We're currently storing its name and BTF id.
  struct BTFObj {
    struct btf* btf;
    std::string name;
  };

  // It is often necessary to store a BTF id along with the BTF data containing
  // its definition.
  struct BTFId {
    struct btf* btf;
    __u32 id;
  };

public:
  BTF();
  BTF(BPFtrace* bpftrace);
  ~BTF();

  bool has_data();
  bool has_module_btf();
  bool modules_loaded() const;
  size_t objects_cnt() const
  {
    return btf_objects.size();
  }
  void load_module_btfs(const std::set<std::string>& modules);
  std::string c_def(const std::unordered_set<std::string>& set);
  std::string type_of(const std::string& name, const std::string& field);
  std::string type_of(const BTFId& type_id, const std::string& field);
  SizedType get_stype(const std::string& type_name);
  SizedType get_var_type(const std::string& var_name);

  std::set<std::string> get_all_structs() const;
  std::unique_ptr<std::istream> get_all_funcs();
  std::unordered_set<std::string> get_all_iters() const;
  std::unique_ptr<std::istream> get_all_raw_tracepoints();
  FuncParamLists get_params(const std::set<std::string>& funcs) const;
  FuncParamLists get_rawtracepoint_params(
      const std::set<std::string>& rawtracepoints) const;

  std::shared_ptr<Struct> resolve_args(const std::string& func,
                                       bool ret,
                                       bool check_traceable,
                                       bool skip_first_arg,
                                       std::string& err);
  std::shared_ptr<Struct> resolve_raw_tracepoint_args(const std::string& func,
                                                      std::string& err);
  void resolve_fields(const SizedType& type);

  int get_btf_id(std::string_view func,
                 std::string_view mod,
                 __u32 kind = BTF_KIND_FUNC) const;

private:
  void load_vmlinux_btf();
  SizedType get_stype(const BTFId& btf_id, bool resolve_structs = true);
  void resolve_fields(const BTFId& type_id,
                      std::shared_ptr<Struct> record,
                      __u32 start_offset);
  const struct btf_type* btf_type_skip_modifiers(const struct btf_type* t,
                                                 const struct btf* btf);
  BTF::BTFId find_id(const std::string& name,
                     std::optional<__u32> kind = std::nullopt) const;
  __s32 find_id_in_btf(struct btf* btf,
                       std::string_view name,
                       std::optional<__u32> kind = std::nullopt) const;

  std::string dump_defs_from_btf(const struct btf* btf,
                                 std::unordered_set<std::string>& types) const;
  std::string get_all_funcs_from_btf(const BTFObj& btf_obj) const;
  std::string get_all_raw_tracepoints_from_btf(const BTFObj& btf_obj) const;
  FuncParamLists get_params_impl(
      const std::set<std::string>& funcs,
      std::function<FuncParamLists(const BTFObj& btf_obj,
                                   const std::set<std::string>& funcs)>
          get_param_btf_cb) const;
  FuncParamLists get_params_from_btf(const BTFObj& btf_obj,
                                     const std::set<std::string>& funcs) const;
  FuncParamLists get_raw_tracepoints_params_from_btf(
      const BTFObj& btf_obj,
      const std::set<std::string>& rawtracepoints) const;
  std::set<std::string> get_all_structs_from_btf(const struct btf* btf) const;
  std::unordered_set<std::string> get_all_iters_from_btf(
      const struct btf* btf) const;
  // Similar to btf_type_skip_modifiers this returns the id of the first
  // type that is not a BTF_KIND_TYPE_TAG while also populating the tags set
  // with the tag/attribute names from the BTF_KIND_TYPE_TAG types it finds.
  __u32 get_type_tags(std::unordered_set<std::string>& tags,
                      const BTFId& btf_id) const;

  __s32 start_id(const struct btf* btf) const;

  struct btf* vmlinux_btf = nullptr;
  __s32 vmlinux_btf_size;
  // BTF objects for vmlinux and modules
  std::vector<BTFObj> btf_objects;
  enum state state = INIT;
  BPFtrace* bpftrace_ = nullptr;
  std::string all_funcs_;
  std::string all_rawtracepoints_;
  std::optional<bool> has_module_btf_;
};

inline bool BTF::has_data()
{
  // This can be called multiple times and won't reload vmlinux
  load_vmlinux_btf();
  return state == VMLINUX_LOADED || state == VMLINUX_AND_MODULES_LOADED;
}

inline bool BTF::modules_loaded() const
{
  return state == VMLINUX_AND_MODULES_LOADED;
}

ast::Pass CreateParseBTFPass();

} // namespace bpftrace
