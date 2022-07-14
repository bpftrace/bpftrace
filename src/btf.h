#pragma once

#include "types.h"
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

  // It is often necessary to store a BTF id along with the BTF data containing
  // its definition.
  struct BTFId
  {
    struct btf* btf;
    __u32 id;
  };

public:
  BTF();
  BTF(BPFtrace* bpftrace) : BTF()
  {
    bpftrace_ = bpftrace;
  };
  ~BTF();

  bool has_data(void) const;
  std::string c_def(const std::unordered_set<std::string>& set) const;
  std::string type_of(const std::string& name, const std::string& field);
  std::string type_of(const BTFId& type_id, const std::string& field);

  std::set<std::string> get_all_structs() const;
  std::unique_ptr<std::istream> get_all_funcs() const;
  std::map<std::string, std::vector<std::string>> get_params(
      const std::set<std::string>& funcs) const;

  void resolve_args(const std::string& func,
                    std::map<std::string, SizedType>& args,
                    bool ret);

  int get_btf_id(const std::string& name) const;

private:
  SizedType get_stype(const BTFId& btf_id);
  const struct btf_type* btf_type_skip_modifiers(const struct btf_type* t,
                                                 const struct btf* btf);
  BTF::BTFId find_id(const std::string& name,
                     std::optional<__u32> kind = std::nullopt) const;
  __s32 find_id_in_btf(struct btf* btf,
                       const std::string& name,
                       std::optional<__u32> = std::nullopt) const;

  std::string dump_defs_from_btf(const struct btf* btf,
                                 std::unordered_set<std::string>& types) const;
  std::string get_all_funcs_from_btf(const struct btf* btf) const;
  std::map<std::string, std::vector<std::string>> get_params_from_btf(
      const struct btf* btf,
      const std::set<std::string>& funcs) const;
  std::set<std::string> get_all_structs_from_btf(const struct btf* btf) const;

  struct btf* vmlinux_btf;
  enum state state = NODATA;
  BPFtrace* bpftrace_ = nullptr;
};

inline bool BTF::has_data(void) const
{
  return state == OK;
}

} // namespace bpftrace
