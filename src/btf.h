#pragma once

#include "types.h"
#include <linux/types.h>
#include <map>
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
  std::string type_of(const btf_type* type, const std::string& field);

  std::set<std::string> get_all_structs() const;
  std::unique_ptr<std::istream> get_all_funcs() const;
  std::map<std::string, std::vector<std::string>> get_params(
      const std::set<std::string>& funcs) const;

  int resolve_args(const std::string &func,
                   std::map<std::string, SizedType>& args,
                   bool ret);

private:
  SizedType get_stype(__u32 id);
  const struct btf_type* btf_type_skip_modifiers(const struct btf_type* t);

  struct btf* btf;
  enum state state = NODATA;
  BPFtrace* bpftrace_ = nullptr;
};

inline bool BTF::has_data(void) const
{
  return state == OK;
}

} // namespace bpftrace
