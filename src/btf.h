#pragma once

#include "types.h"
#include <linux/types.h>
#include <map>
#include <regex>
#include <string>
#include <unistd.h>
#include <unordered_set>

struct btf;
struct btf_type;

namespace bpftrace {

class BTF
{
  enum state
  {
    NODATA,
    OK,
  };

public:
  BTF();
  ~BTF();

  bool has_data(void) const;
  std::string c_def(const std::unordered_set<std::string>& set) const;
  std::string type_of(const std::string& name, const std::string& field);
  std::string type_of(const btf_type* type, const std::string& field);
  void display_kfunc(std::regex* re) const;
  void display_lsm(std::regex* re) const;
  void display_structs(std::regex* re) const;

  std::unique_ptr<std::istream> kfunc(void) const;
  std::unique_ptr<std::istream> lsm(void) const;

  int resolve_args(const std::string &func,
                   std::map<std::string, SizedType>& args,
                   bool ret);

private:
  SizedType get_stype(__u32 id);
  const struct btf_type* btf_type_skip_modifiers(const struct btf_type* t);
  std::unique_ptr<std::istream> get_funcs(std::regex* re,
                                          bool params,
                                          bool lsm,
                                          std::string prefix) const;

  struct btf* btf;
  enum state state = NODATA;
};

inline bool BTF::has_data(void) const
{
  return state == OK;
}

} // namespace bpftrace
